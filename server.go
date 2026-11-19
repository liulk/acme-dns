package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/liulk/acme-dns/internal/registry"
)

type serverConfig struct {
	domain      string
	registryDir string
	dnsSecKSK   string
	dnsSecZSK   string
	dnsAddr     string
	apiAddr     string
	apiCert     string
	apiKey      string
	allowFrom   string
	keep        int
}

func (c *serverConfig) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.domain, "domain", "", "serves authoritative DNS for this domain (required)")
	fs.StringVar(&c.registryDir, "registry_dir", "", "reads the registrations from this directory (required)")
	fs.StringVar(&c.dnsSecKSK, "dnssec_ksk", "", "enables DNSSEC using this key signing key in openssh PEM format; referenced by parent DS")
	fs.StringVar(&c.dnsSecZSK, "dnssec_zsk", "", "uses this zone signing key in openssh PEM format")
	fs.StringVar(&c.dnsAddr, "dns_addr", ":5300", "listens for DNS at this address, to be reached by ACME CA")
	fs.StringVar(&c.apiAddr, "api_addr", "localhost:8000", "listens for the DNS update HTTP API at this address, to be used by ACME clients to publish challenge tokens")
	fs.StringVar(&c.apiCert, "api_tls_cert", "", "optional TLS cert for the HTTP API")
	fs.StringVar(&c.apiKey, "api_tls_key", "", "optional TLS private key for the HTTP API")
	fs.StringVar(&c.allowFrom, "allow_from", "127.0.0.1/8,::1/128", "comma separated netblocks permitted for API client source")
	fs.IntVar(&c.keep, "keep", 2, "keeps the most recent number of TXT values updated through the API")
}

func (c *serverConfig) newServer(ctx context.Context) *server {
	var errs []error
	var s server

	s.serverConfig = *c
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.txtrecs = make(map[dnsmessage.Name][][]string)

	domain := c.domain
	if domain == "" {
		errs = append(errs, errors.New("missing required -domain"))
	} else {
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		name, err := dnsmessage.NewName(domain)
		if err != nil {
			errs = append(errs, err)
		} else {
			s.domain = name
		}
	}

	if s.registryDir == "" {
		errs = append(errs, errors.New("missing required -registry_dir"))
	} else if st, err := os.Stat(s.registryDir); err != nil {
		errs = append(errs, fmt.Errorf("bad -registry_dir: %w", err))
	} else if !st.IsDir() {
		errs = append(errs, fmt.Errorf("not a directory -registry_dir: %s", s.registryDir))
	} else {
		s.registry = registry.Registry(s.registryDir)
	}

	if s.dnsSecKSK != "" {
		if b, err := os.ReadFile(s.dnsSecKSK); err != nil {
			errs = append(errs, fmt.Errorf("bad -dnssec_ksk: %w", err))
		} else if signer, err := ssh.ParsePrivateKey(b); err != nil {
			errs = append(errs, fmt.Errorf("error parsing -dnssec_ksk %s: %w", s.dnsSecKSK, err))
		} else {
			s.dnsSecKeySigner = signer
		}
	}

	if s.dnsSecZSK != "" {
		if b, err := os.ReadFile(s.dnsSecZSK); err != nil {
			errs = append(errs, fmt.Errorf("bad -dnssec_zsk: %w", err))
		} else if signer, err := ssh.ParsePrivateKey(b); err != nil {
			errs = append(errs, fmt.Errorf("error parsing -dnssec_zsk %s: %w", s.dnsSecZSK, err))
		} else {
			s.dnsSecZoneSigner = signer
		}
	}

	if s.dnsSecZoneSigner == nil {
		s.dnsSecZoneSigner = s.dnsSecKeySigner
	}

	if addr, err := net.ResolveUDPAddr("udp", c.dnsAddr); err != nil {
		errs = append(errs, fmt.Errorf("bad -dns_addr: %w", err))
	} else {
		s.dnsAddr = addr
	}

	if addr, err := net.ResolveTCPAddr("tcp", c.apiAddr); err != nil {
		errs = append(errs, fmt.Errorf("bad -api_addr: %w", err))
	} else {
		s.apiAddr = addr
	}

	s.allowFrom = strings.Split(c.allowFrom, ",")
	nets, err := parsePrefixes(s.allowFrom)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing -allow_from: %w", err))
	}
	s.allowFromNets = nets
	s.err = errors.Join(errs...)
	return &s
}

func parsePrefixes(prefixes []string) (nets []netip.Prefix, err error) {
	var errs []error
	for _, prefix := range prefixes {
		if net, err := netip.ParsePrefix(prefix); err != nil {
			errs = append(errs, err)
		} else {
			nets = append(nets, net)
		}
	}
	return nets, errors.Join(errs...)
}

const dnsRCodeMax = dnsmessage.RCodeRefused + 1

type server struct {
	serverConfig

	err    error
	ctx    context.Context
	cancel context.CancelFunc

	domain           dnsmessage.Name
	registry         registry.Registry
	dnsSecKeySigner  ssh.Signer
	dnsSecZoneSigner ssh.Signer
	dnsAddr          *net.UDPAddr
	apiAddr          *net.TCPAddr
	allowFrom        []string
	allowFromNets    []netip.Prefix

	mu      sync.RWMutex
	txtrecs map[dnsmessage.Name][][]string // each TXT record is a sequence of string fragments.

	dnsServReadError  atomic.Uint64
	dnsRespPackError  atomic.Uint64
	dnsRespWriteError atomic.Uint64

	dnsRCode [dnsRCodeMax]atomic.Uint64

	dnsReqSOA     atomic.Uint64
	dnsReqNotTXT  atomic.Uint64
	dnsReqNotINET atomic.Uint64
}

func (s *server) serve() error {
	defer s.cancel()

	if s.err != nil {
		return s.err
	}

	log.Printf("DNS server: listening on %s", s.dnsAddr)
	dnsConn, err := net.ListenUDP("udp", s.dnsAddr)
	if err != nil {
		return fmt.Errorf("dns server: %w", err)
	}
	for range runtime.GOMAXPROCS(0) {
		go s.serveDNS(dnsConn)
	}

	srv := s.apiServer()
	go func() {
		if s.apiCert != "" {
			log.Printf("API server: listening with TLS on %s", srv.Addr)
			err = srv.ListenAndServeTLS(s.apiCert, s.apiKey)
		} else {
			log.Printf("API server: listening on %s", srv.Addr)
			err = srv.ListenAndServe()
		}
		if err != nil {
			log.Printf("Server: %v", err)
		}
	}()

	<-s.ctx.Done()

	// Wake up dnsConn.ReadFromUDP which should quit in the next iteration.
	dnsConn.SetReadDeadline(time.Now())
	return srv.Shutdown(s.ctx)
}

func (s *server) apiServer() *http.Server {
	return &http.Server{
		Addr:        s.serverConfig.apiAddr,
		BaseContext: func(_ net.Listener) context.Context { return s.ctx },
		Handler:     s.apiMux(),
	}
}

func (s *server) apiMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.enforceAllowFrom(s.apiHandleRegister))
	mux.HandleFunc("POST /update", s.enforceAllowFrom(s.apiHandleUpdate))
	return mux
}

func (s *server) enforceAllowFrom(h http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		addrport, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			serveResponse(w, http.StatusBadRequest, &apiData{Error: err.Error()})
			return
		}
		if !anyPrefix(addrport.Addr(), s.allowFromNets) {
			serveResponse(w, http.StatusForbidden, &apiData{
				Error: fmt.Sprintf("client not allowed: %s", r.RemoteAddr),
			})
			return
		}
		if ct := r.Header.Get("content-type"); ct != "application/json" {
			serveResponse(w, http.StatusBadRequest, &apiData{
				Error: fmt.Sprintf("bad request content-type: %s", ct),
			})
		}
		h(w, r)
	}
}

func anyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type apiData struct {
	registry.Record
	Error string `json:"error,omitempty"`
}

func serveResponse(w http.ResponseWriter, status int, resp *apiData) {
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Too late to call http.Error since the header has already been written.
		log.Printf("Error: encoding JSON: %v", err)
	}
}

func parseJSON(r io.ReadCloser) (*apiData, error) {
	defer r.Close()
	var req apiData
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

func (s *server) apiHandleRegister(w http.ResponseWriter, r *http.Request) {
	_, err := parseJSON(r.Body)
	if err != nil {
		serveResponse(w, http.StatusBadRequest, &apiData{
			Error: fmt.Sprintf("JSON parse error: %v", err)})
		return
	}

	rec, err := registry.NewRecord(strings.TrimSuffix(s.domain.String(), "."))
	if err != nil {
		serveResponse(w, http.StatusInternalServerError, &apiData{Error: err.Error()})
		return
	}
	rec.AllowFrom = s.allowFrom
	serveResponse(w, http.StatusCreated, &apiData{Record: *rec})
}

func (s *server) apiHandleUpdate(w http.ResponseWriter, r *http.Request) {
	req, err := parseJSON(r.Body)
	if err != nil {
		serveResponse(w, http.StatusBadRequest, &apiData{
			Error: fmt.Sprintf("JSON parse error: %v", err)})
		return
	}
	if u := r.Header.Get("x-api-user"); u != "" {
		req.Username = u
	}
	if p := r.Header.Get("x-api-key"); p != "" {
		req.Password = p
	}

	name, err := dnsmessage.NewName(req.Subdomain + "." + s.domain.String())
	if err != nil {
		serveResponse(w, http.StatusBadRequest, &apiData{Error: fmt.Sprintf("bad DNS name: %v", err)})
		return
	}

	recs, err := s.registry.Read(req.Subdomain)
	if err != nil {
		log.Printf("Error: reading registry: %v", err)
		serveResponse(w, http.StatusInternalServerError, &apiData{Error: "registry read error"})
		return
	}

	if len(recs) == 0 {
		serveResponse(w, http.StatusNotFound, &apiData{
			Error: fmt.Sprintf("subdomain not found: %s", req.Subdomain),
		})
		return
	}

	fulldomain := strings.TrimSuffix(name.String(), ".")
	for _, rec := range recs {
		if rec.FullDomain != fulldomain {
			log.Printf("Warning: mismatched fulldomain: got %s, want %s", rec.FullDomain, fulldomain)
		}
		if rec.Username == "" || rec.Password == "" {
			continue // FIXED: empty username or password should not make the entry updatable.
		}
		if rec.Username != req.Username {
			continue
		}
		if rec.Password != req.Password {
			continue
		}

		log.Printf("Update: %s: %s: %s TXT %q", r.RemoteAddr, rec.Username, name, req.TXT)
		s.addTXTRec(name, req.PreferredTXTs())
		serveResponse(w, http.StatusOK, &apiData{TXT: req.TXT, TXTs: req.TXTs})
		return
	}

	serveResponse(w, http.StatusForbidden, &apiData{
		Error: fmt.Sprintf("no valid credentials found for subdomain: %s", req.Subdomain),
	})
}

func (s *server) addTXTRec(name dnsmessage.Name, txts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	txtrecs := s.txtrecs[name]
	txtrecs = append(txtrecs, txts)
	if l := len(txtrecs); l > s.keep {
		txtrecs = slices.Clone(txtrecs[l-s.keep:])
	}
	s.txtrecs[name] = txtrecs
}

func (s *server) getDynamicTXTRecs(name dnsmessage.Name) [][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.txtrecs[name])
}

func (s *server) getTXTRecs(name dnsmessage.Name) [][]string {
	txtrecs := s.getDynamicTXTRecs(name)

	subdomain := strings.TrimSuffix(name.String(), "."+s.domain.String())
	recs, _ := s.registry.Read(subdomain)
	for _, rec := range recs {
		if txts := rec.PreferredTXTs(); len(txts) > 0 {
			txtrecs = append(txtrecs, txts)
		}
	}
	return txtrecs
}
