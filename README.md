# caa
CAA check module in Golang.

## Notes
Initial CAA checker commit.
Many things to do...

## ResponseCodes:
0 = NOERR, no error
1 = FORMERR, format error (unable to understand the query)
2 = SERVFAIL, name server problem
3 = NXDOMAIN, domain name does not exist
4 = NOTIMPL, not implemented
5 = REFUSED (e.g., refused zone transfer requests)