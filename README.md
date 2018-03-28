# bns

DNS library and validating recursive resolver for node.js, in pure javascript.

## Example

``` bash
$ rdig.js www.ietf.org +dnssec +debug
Querying www.ietf.org./A.
Verifying zone change to [.]
Checking signatures...
Retrying over TCP (2001:503:ba3e::2:30): 19235.
Validated DNSSEC signatures.
Switching authority: [2001:500:40::1] (d0.org.afilias-nst.org.)
Switching zone: [.->org.]
Verifying zone change to [org.]
Checking signatures...
Validated DNSSEC signatures.
Looking up NS: ns1.mia1.afilias-nst.info.
Looking up IPv6 nameserver for ns1.mia1.afilias-nst.info....
Querying ns1.mia1.afilias-nst.info./AAAA.
Verifying zone change to [.]
Checking signatures...
Cache hit for ./DNSKEY.
Validated DNSSEC signatures.
Switching authority: [199.254.48.1] (b0.info.afilias-nst.org.)
Switching zone: [.->info.]
Verifying zone change to [info.]
Checking signatures...
Validated DNSSEC signatures.
Validated NSEC3 delegation.
Switching authority: [2a01:8840:6::1] (d0.dig.afilias-nst.info.)
Switching zone: [info.->afilias-nst.info.]
Trust chain broken due to zone change.
Traversed zones: ., info., afilias-nst.info. for ns1.mia1.afilias-nst.info./AAAA.
Picked nameserver: 2a01:8840:7::1.
Switching authority: [2a01:8840:7::1] (ns1.mia1.afilias-nst.info.)
Switching zone: [org.->ietf.org.]
Verifying zone change to [ietf.org.]
Checking signatures...
Validated DNSSEC signatures.
Found alias to: www.ietf.org.cdn.cloudflare.net.
Alias changing zone: [ietf.org.->.]
Verifying zone change to [.]
Checking signatures...
Cache hit for ./DNSKEY.
Validated DNSSEC signatures.
Switching authority: [192.54.112.30] (l.gtld-servers.net.)
Switching zone: [.->net.]
Verifying zone change to [net.]
Checking signatures...
Validated DNSSEC signatures.
Switching authority: [2400:cb00:2049:1::c629:de1f] (ns5.cloudflare.net.)
Switching zone: [net.->cloudflare.net.]
Verifying zone change to [cloudflare.net.]
Checking signatures...
Validated DNSSEC signatures.
Traversed zones: ., org., ietf.org., ., net., cloudflare.net. for www.ietf.org./A.
Finishing resolving www.ietf.org./A (hops=8).

; <<>> rdig.js 0.0.5 <<>> www.ietf.org +dnssec +debug
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28579
;; flags: qr ra ad, QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do, udp: 512
;; QUESTION SECTION:
;www.ietf.org. IN A

;; ANSWER SECTION:
www.ietf.org. 1800 IN CNAME www.ietf.org.cdn.cloudflare.net.
www.ietf.org. 1800 IN RRSIG CNAME 5 3 1800 20190214160829 20180214150920 40452 ietf.org. OAS6hbpld1KpNJBpqg/T+0m0FpcVV933AbsDuVlgloHQfyVG4Ug5iOtK QLKGNYw+583Ba1yhFlFsYu4GNALZFpF8Tw5NcmxpmXJyzpeO0aj1rSCH oFQzYaIszrbw7TmE2pYQbh9QeklO9hILxi/Q1D7VxzrtHj0Ff8ncgFI7 6Ep+ud0Gysr0m/5MrwO69LGPV06LTuMRP3cXv7hqbjmyn2CmYR3h6+lQ +uiHSwkZYK20xhk+w1pOP9CD6fIqGYCJiKVaMY8K2lMQyi6Ppx0zOmtk MdaJjnxrzQ5TXbCcGQ48Rn4hzdug1MvkJzh1DGWZH6ZnPQTEf3+O1ehz +zSpbQ==  ; alg = RSASHA1
www.ietf.org.cdn.cloudflare.net. 300 IN A 104.20.1.85
www.ietf.org.cdn.cloudflare.net. 300 IN A 104.20.0.85
www.ietf.org.cdn.cloudflare.net. 300 IN RRSIG A 13 6 300 20180329050317 20180327030317 35273 cloudflare.net. cp0elWqesQt1uNBhyhRd7Zpks7UzVc0xSqxTKBsKnpb7WWgdqZD/kq+s JWTE+POxzoJ2jSUhFSjWL4C+7o24KQ==  ; alg = ECDSAP256SHA256

;; Query time: 766 msec
;; WHEN: Tue Mar 27 21:03:03 PDT 2018
;; MSG SIZE  rcvd: 641
```

## Usage

``` js
const bns = require('bns');
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
