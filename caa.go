package pkicaa

import (
	"net"
	"strings"

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

	if caadata.DNSSEC == true && r.AuthenticatedData == false {
		caacontrol := new(control)
		caacontrol.Message = "DNSSEC valid on domain but invalid on subdomain " + hostname + ". CA may not issue."
		caacontrol.Blocking = true
		caadata.Controls = append(caadata.Controls, caacontrol)
		caadata.Blocking = true
	}

	if caadata.DNSSEC == true {
		switch r.Rcode {
		case 0:
			// nothing
		case 1:
			caacontrol := new(control)
			caacontrol.Message = "DNS code 1, FORMERR, if DNSSEC is on, CA may not issue."
			caacontrol.Blocking = true
			caadata.Controls = append(caadata.Controls, caacontrol)
			caadata.Blocking = true
		case 2:
			caacontrol := new(control)
			caacontrol.Message = "DNS code 2, SERVFAIL, if DNSSEC is on, CA may not issue."
			caacontrol.Blocking = true
			caadata.Controls = append(caadata.Controls, caacontrol)
			caadata.Blocking = true
		case 3:
			// nothing
		case 4:
			caacontrol := new(control)
			caacontrol.Message = "DNS code 4, NOTIMPL, if DNSSEC is on, CA may not issue."
			caacontrol.Blocking = true
			caadata.Controls = append(caadata.Controls, caacontrol)
		case 5:
			caacontrol := new(control)
			caacontrol.Message = "DNS code 5, REFUSED, if DNSSEC is on, CA may not issue."
			caacontrol.Blocking = true
			caadata.Controls = append(caadata.Controls, caacontrol)
			caadata.Blocking = true
		default:
			caacontrol := new(control)
			caacontrol.Message = "Unknown DNS code, if DNSSEC is on, CA may not issue."
			caacontrol.Blocking = true
			caadata.Controls = append(caadata.Controls, caacontrol)
			caadata.Blocking = true
		}
	}

	if r.Rcode != dns.RcodeSuccess {
		return hostdata, err
	}

	for _, ain := range r.Answer {
		if a, ok := ain.(*dns.CAA); ok {
			recorddata := new(caarecord)
			recorddata.Flag = a.Flag
			recorddata.Tag = strings.ToLower(a.Tag)
			recorddata.Value = strings.ToLower(a.Value)
			hostdata.CAArecords = append(hostdata.CAArecords, recorddata)
		}
	}

	cnametarget, _ := getCNAME(hostname, nameserver)
	hostdata.CNAME = cnametarget

	dnametarget, _ := getDNAME(hostname, nameserver)
	hostdata.DNAME = dnametarget

	return hostdata, nil
}
