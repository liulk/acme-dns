package main

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

func (s *server) serveDNS(conn *net.UDPConn) error {
	// Standard DNS UDP payload limit is 512 bytes (without EDNS0)
	buf := make([]byte, 512)
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

func (s *server) dnsHandle(conn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte) {
	var req dnsmessage.Message
	var resp dnsmessage.Message
	resp.RCode = dnsmessage.RCodeServerFailure // catch-all

	defer func() {
		resp.ID = req.ID
		resp.Response = true
		resp.Authoritative = true
		resp.RecursionDesired = req.RecursionDesired
		resp.RecursionAvailable = false

		if rcode := resp.RCode; int(rcode) < len(s.dnsRCode) {
			s.dnsRCode[rcode].Add(1)
		}

		packed, err := resp.Pack()
		if err != nil {
			s.dnsRespPackError.Add(1)
			return
		}
		if _, err := conn.WriteToUDP(packed, clientAddr); err != nil {
			s.dnsRespWriteError.Add(1)
			return
		}
	}()

	err := req.Unpack(packet)
	if err != nil {
		resp.RCode = dnsmessage.RCodeFormatError
		return
	}
	if req.Response {
		resp.RCode = dnsmessage.RCodeRefused
		return
	}
	if len(req.Questions) != 1 {
		resp.RCode = dnsmessage.RCodeNotImplemented
		return
	}

	resp.Questions = req.Questions
	question := req.Questions[0]

	txtrecs := s.getTXTRecs(question.Name)
	if txtrecs == nil {
		resp.RCode = dnsmessage.RCodeNameError
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
