package main

import (
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func (s *server) serveDNS(conn *net.UDPConn) error {
	buf := make([]byte, 4096)
	for {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			s.dnsServReadError.Add(1)
			continue
		}
		s.dnsHandle(conn, srcAddr, buf[:n])
	}
}

func opt(msg *dnsmessage.Message) (optr *dnsmessage.Resource, ok bool) {
	for i := range msg.Additionals {
		add := &msg.Additionals[i]
		if add.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		return add, true
	}
	return nil, false
}

func (s *server) dnsWrite(conn *net.UDPConn, addr *net.UDPAddr, req, resp *dnsmessage.Message) {
	resp.ID = req.ID
	resp.Response = true
	resp.Authoritative = true
	resp.RecursionDesired = req.RecursionDesired
	resp.RecursionAvailable = false

	if rcode := resp.RCode; int(rcode) < len(s.dnsRCode) {
		s.dnsRCode[rcode].Add(1)
	}

	optr, ok := opt(resp)
	if ok {
		plen, dnssec := int(optr.Header.Class), optr.Header.DNSSECAllowed()
		if s.dnsSecZoneSigner == nil {
			dnssec = false
		}
		optr.Header.SetEDNS0(plen, resp.RCode /* discards lower 4 bits */, dnssec)
	}

	resp.RCode &= 15 // resp.Pack() does not truncate rcode
	packed, err := resp.Pack()
	if err != nil {
		s.dnsRespPackError.Add(1)
		return
	}
	if _, err := conn.WriteToUDP(packed, addr); err != nil {
		s.dnsRespWriteError.Add(1)
		return
	}
}

func (s *server) dnsHandle(conn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte) {
	var req dnsmessage.Message
	var resp dnsmessage.Message

	resp.Authorities = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name:  s.domain,
			Type:  dnsmessage.TypeSOA,
			Class: dnsmessage.ClassINET,
			TTL:   30,
		},
		Body: &dnsmessage.SOAResource{
			NS:      s.domain,
			MBox:    s.domain,
			Serial:  uint32(time.Now().Unix()),
			Refresh: 30,
			Retry:   30,
			Expire:  3600000,
			MinTTL:  1,
		},
	}}
	resp.RCode = dnsmessage.RCodeServerFailure // catch-all
	defer s.dnsWrite(conn, clientAddr, &req, &resp)

	err := req.Unpack(packet)
	if err != nil {
		resp.RCode = dnsmessage.RCodeFormatError
		return
	}
	optr, opt := opt(&req)
	if opt {
		resp.Additionals = []dnsmessage.Resource{*optr}
	}

	if req.Response {
		resp.RCode = dnsmessage.RCodeRefused
		return
	}
	if len(req.Questions) != 1 {
		resp.RCode = dnsmessage.RCodeNotImplemented
		return
	}

	resp.RCode = dnsmessage.RCodeNameError
	resp.Questions = req.Questions
	question := req.Questions[0]

	if question.Name == s.domain {
		resp.RCode = dnsmessage.RCodeSuccess
		if question.Type == dnsmessage.TypeSOA {
			resp.Answers = resp.Authorities
			resp.Authorities = nil
			s.dnsReqSOA.Add(1)
		}
		return
	}

	txtrecs := s.getTXTRecs(question.Name)
	if txtrecs == nil {
		return
	}
	resp.RCode = dnsmessage.RCodeSuccess

	if question.Type != dnsmessage.TypeTXT {
		s.dnsReqNotTXT.Add(1)
		return
	}
	if question.Class != dnsmessage.ClassINET {
		s.dnsReqNotINET.Add(1)
		return
	}

	for _, txts := range txtrecs {
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  question.Type,
				Class: question.Class,
				TTL:   30,
			},
			Body: &dnsmessage.TXTResource{
				TXT: txts, // acme DNS-PERSIST-01 needs TXT as fragments.
			},
		})
	}

	// Let defer tally the RCode and write the resp back to client.
}
