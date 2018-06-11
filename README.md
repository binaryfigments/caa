# CAA

CAA check library in Golang. Using https://github.com/miekg/dns for the DNS lookups.

## Notes

Initial CAA checker commit.
Many things to do...

## DNS ResponseCodes

Here some DNS response codes, maybe I have to map them later.

```text
0 = NOERR, no error
1 = FORMERR, format error (unable to understand the query)
2 = SERVFAIL, name server problem
3 = NXDOMAIN, domain name does not exist
4 = NOTIMPL, not implemented
5 = REFUSED (e.g., refused zone transfer requests)
```

## CA information

Some CA's seem to check different then others. Not all resolving nameservers are giving the same answers.
