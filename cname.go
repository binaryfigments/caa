package pkicaa

import (
	"net"

	"github.com/miekg/dns"
)

func getCNAME(hostname string, nameserver string) (string, error) {
	var cnamerecord string

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		return "", err
	}

	for _, ain := range r.Answer {
		if a, ok := ain.(*dns.CNAME); ok {
			cnamerecord = a.Target
		}
	}

	return cnamerecord, nil
}
