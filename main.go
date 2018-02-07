package pkicaa

import (
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type CAAdata struct {
	Domain       string  `json:"domain,omitempty"`
	Hosts        []*host `json:"host,omitempty"`
	Error        string  `json:"error,omitempty"`
	ErrorMessage string  `json:"errormessage,omitempty"`
}

type host struct {
	Hostname          string        `json:"hostname,omitempty"`
	CAAraw            dns.RR        `json:"caaraw,omitempty"`
	CAArecords        []*caarecords `json:"caarecords,omitempty"`
	AuthenticatedData bool          `json:"authenticated_data,omitempty"`
	ResponseCode      int           `json:"responsecode"`
	CNAME             string        `json:"cname,omitempty"`
	DNAME             string        `json:"dname,omitempty"`
}

type caarecords struct {
	Flag  uint8  `json:"flag,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value,omitempty"`
}

// Get function, main function of this module.
func Get(hostname string, nameserver string) *CAAdata {
	caadata := new(CAAdata)

	caadata.Domain = hostname

	var dnsnames []string
	dnsnames = append(dnsnames, hostname)

	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		caadata.Error = "Error"
		caadata.ErrorMessage = err.Error()
		return caadata
	}

	tophostinfo, err := getCAA(hostname, domain, nameserver)
	if err != nil {
		caadata.Error = "Error"
		caadata.ErrorMessage = err.Error()
		return caadata
	}
	caadata.Hosts = append(caadata.Hosts, tophostinfo)

	if domain != hostname {
		hostdata := new(host)
		hostdata.Hostname = hostname

		hosts := strings.TrimSuffix(hostname, "."+domain)
		hostscount := len(strings.Split(hosts, "."))

		sum := 1
		for sum < hostscount {
			sum++
			hostparts := strings.Split(hosts, ".")
			hosts = strings.TrimPrefix(hosts, hostparts[0]+".")
			dnsnames = append(dnsnames, hosts+"."+domain)

			hostinfo, err := getCAA(hosts+"."+domain, domain, nameserver)
			if err != nil {
				caadata.Error = "Error"
				caadata.ErrorMessage = err.Error()
				return caadata
			}
			caadata.Hosts = append(caadata.Hosts, hostinfo)
		}
		dnsnames = append(dnsnames, domain)

		domaininfo, err := getCAA(domain, domain, nameserver)
		if err != nil {
			caadata.Error = "Error"
			caadata.ErrorMessage = err.Error()
			return caadata
		}
		caadata.Hosts = append(caadata.Hosts, domaininfo)
	}
	return caadata
}
