package pkicaa

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// CAAdata struct is the main struct
type CAAdata struct {
	Domain       string     `json:"domain"`
	DNSSEC       bool       `json:"dnssec"`
	Blocking     bool       `json:"blocking,omitempty"`
	Found        bool       `json:"found,omitempty"`
	Issue        []string   `json:"issue,omitempty"`
	IssueWild    []string   `json:"issuewild,omitempty"`
	Hosts        []*host    `json:"host,omitempty"`
	Controls     []*control `json:"control,omitempty"`
	Error        string     `json:"error,omitempty"`
	ErrorMessage string     `json:"errormessage,omitempty"`
}

type host struct {
	Hostname          string       `json:"hostname,omitempty"`
	CAArecords        []*caarecord `json:"caarecords,omitempty"`
	AuthenticatedData bool         `json:"authenticated_data,omitempty"`
	ResponseCode      int          `json:"responsecode"`
	CNAME             string       `json:"cname,omitempty"`
	DNAME             string       `json:"dname,omitempty"`
}

type control struct {
	Message  string `json:"message,omitempty"`
	Blocking bool   `json:"blocking,omitempty"`
}

type caarecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value,omitempty"`
}

var caadata = new(CAAdata)

// Get function, main function of this module.
func Get(hostname string, nameserver string, full bool) *CAAdata {
	// caadata := new(CAAdata)
	hostname = strings.ToLower(hostname)

	var issue []string
	var issuewild []string

	caadata.Domain = hostname

	var dnsnames []string
	dnsnames = append(dnsnames, hostname)

	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		caadata.Error = "Error"
		caadata.ErrorMessage = err.Error()
		return caadata
	}

	ns, isdnssec, err := checkDomain(domain, nameserver)
	if err != nil {
		caadata.Error = "Error"
		caadata.ErrorMessage = err.Error()
		return caadata
	}

	caadata.DNSSEC = isdnssec
	if caadata.DNSSEC == true {
		caacontrol := new(control)
		caacontrol.Message = "DNSSEC found on domain, no DNS errors may occur."
		caacontrol.Blocking = false
		caadata.Controls = append(caadata.Controls, caacontrol)
	}

	if ns == "" {
		caadata.Error = "Error"
		caadata.ErrorMessage = "No NS record in SOA"
		return caadata
	}

	domain, err = idna.ToASCII(domain)
	if err != nil {
		caadata.Error = "Failed"
		caadata.ErrorMessage = err.Error()
		return caadata
	}

	domaininfo, err := getCAA(domain, domain, nameserver)
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
	if len(tophostinfo.CAArecords) > 0 && full == false {
		caadata.Found = true
		for _, value := range tophostinfo.CAArecords {
			if value.Tag == "issue" {
				// valueca := strings.Split(value.Value, ";")
				issue = append(issue, value.Value)
			} else if value.Tag == "issuewild" {
				issuewild = append(issuewild, value.Value)
			}

		}
		caadata.Issue = issue
		caadata.IssueWild = issuewild
		return caadata
	}

	if tophostinfo.CNAME != "" {
		cname := strings.TrimSuffix(tophostinfo.CNAME, ".")
		cnameinfo, err := getCAA(cname, domain, nameserver)
		if err != nil {
			caadata.Error = "Error"
			caadata.ErrorMessage = err.Error()
			return caadata
		}

		caadata.Hosts = append(caadata.Hosts, cnameinfo)
		if len(tophostinfo.CAArecords) > 0 && full == false {
			caadata.Found = true
			for _, value := range tophostinfo.CAArecords {
				if value.Tag == "issue" {
					// valueca := strings.Split(value.Value, ";")
					issue = append(issue, value.Value)
				} else if value.Tag == "issuewild" {
					issuewild = append(issuewild, value.Value)
				}

			}
			caadata.Issue = issue
			caadata.IssueWild = issuewild
			return caadata
		}
	}

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

			if hostinfo.CNAME != "" {
				cname := strings.TrimSuffix(hostinfo.CNAME, ".")
				cnameinfo, err := getCAA(cname, domain, nameserver)
				if err != nil {
					caadata.Error = "Error"
					caadata.ErrorMessage = err.Error()
					return caadata
				}

				caadata.Hosts = append(caadata.Hosts, cnameinfo)
				if len(tophostinfo.CAArecords) > 0 && full == false {
					caadata.Found = true
					for _, value := range tophostinfo.CAArecords {
						if value.Tag == "issue" {
							// valueca := strings.Split(value.Value, ";")
							issue = append(issue, value.Value)
						} else if value.Tag == "issuewild" {
							issuewild = append(issuewild, value.Value)
						}

					}
					caadata.Issue = issue
					caadata.IssueWild = issuewild
					return caadata
				}
			}

			caadata.Hosts = append(caadata.Hosts, hostinfo)
			if len(hostinfo.CAArecords) > 0 && full == false {
				caadata.Found = true
				for _, value := range hostinfo.CAArecords {
					if value.Tag == "issue" {
						// valueca := strings.Split(value.Value, ";")
						issue = append(issue, value.Value)
					} else if value.Tag == "issuewild" {
						issuewild = append(issuewild, value.Value)
					}

				}
				caadata.Issue = issue
				caadata.IssueWild = issuewild
				return caadata
			}
		}
		dnsnames = append(dnsnames, domain)

		caadata.Hosts = append(caadata.Hosts, domaininfo)

		if len(domaininfo.CAArecords) > 0 && full == false {
			caadata.Found = true
			for _, value := range domaininfo.CAArecords {
				if value.Tag == "issue" {
					// valueca := strings.Split(value.Value, ";")
					issue = append(issue, value.Value)
				} else if value.Tag == "issuewild" {
					issuewild = append(issuewild, value.Value)
				}

			}
			caadata.Issue = issue
			caadata.IssueWild = issuewild
			return caadata
		}
	}
	return caadata
}
