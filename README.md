#### dq tool ####
* based on dnsq and dnsqr from djbdns
* added IPv6 support
* added DNSCurve support (Streamlined/TXT)

#### dqcache recursive server ####
* based on dnscache from djbdns
* added support for streamlined DNSCurve
* added support for TXT DNSCurve
* added support for combined DNSCurve (streamlined and TXT)
* added support for DNS anchors with DNSCurve keys
* added full IPv6 support
* added support for IPv6 DNS anchors
* added support for cache dumping/loading
* used siphash24 instead of hash5381 in cache library
* added SOA record caching
* added authority record to DNS response
* improved logs - IPs not printed in hex format
* fixed CVE-2012-1191
* fixed CVE-2008-4392

#### examples ####
- [examples page](examples.md)

#### installation ####
- [installation](install.md)

#### licence ####
* Dq is derived from public-domain djbdns-1.05 - see: https://cr.yp.to/distributors.html
* Dq is released under CC0 licence http://creativecommons.org/publicdomain/zero/1.0/
