package pkicaa

import (
	"net"

	"github.com/miekg/dns"
)

func getCAA(hostname string, domain string, nameserver string) (*host, error) {
	hostdata := new(host)
	hostdata.Hostname = hostname

	// Starting DNS dingen
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeCAA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return hostdata, err
	}

	hostdata.AuthenticatedData = r.AuthenticatedData
	hostdata.ResponseCode = r.Rcode

	if r.Rcode != dns.RcodeSuccess {
		return hostdata, err
	}

	for _, ain := range r.Answer {
		if a, ok := ain.(*dns.CAA); ok {
			recorddata := new(caarecords)
			recorddata.Flag = a.Flag
			recorddata.Tag = a.Tag
			recorddata.Value = a.Value
			hostdata.CAArecords = append(hostdata.CAArecords, recorddata)
		}
	}

	cnametarget, _ := getCNAME(hostname, nameserver)
	hostdata.CNAME = cnametarget

	dnametarget, _ := getDNAME(hostname, nameserver)
	hostdata.DNAME = dnametarget

	return hostdata, nil
}
