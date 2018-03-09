# bns

DNS library and recursive resolver for node.js, in pure javascript.

## Example

``` bash
$ ./bin/rdig.js google.com
Querying google.com./255.
Verifying zone change to [.]
Checking signatures...
Validated DNSSEC signatures.
Switching authority: [192.41.162.30] (c.gtld-servers.net.)
Switching zone: [.->com.]
Verifying zone change to [com.]
Checking signatures...
Validated DNSSEC signatures.
Switching authority: [216.239.36.10] (ns3.google.com.)
Switching zone: [com.->google.com.]
Trust chain broken due to zone change.
Traversed zones: ., com., google.com. for google.com./255.
Finishing resolving google.com./255 (hops=2).
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 0
;; flags: qr ra, QUERY: 1, ANSWER: 15, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
; google.com. IN ANY

;; ANSWER SECTION:
google.com. 300 IN A 172.217.0.46
google.com. 300 IN AAAA 2607:f8b0:4005:802::200e
google.com. 300 IN TXT "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
google.com. 600 IN MX 20 alt1.aspmx.l.google.com.
google.com. 345600 IN NS ns1.google.com.
google.com. 3600 IN TXT "v=spf1 include:_spf.google.com ~all"
google.com. 600 IN MX 40 alt3.aspmx.l.google.com.
google.com. 345600 IN NS ns3.google.com.
google.com. 600 IN MX 30 alt2.aspmx.l.google.com.
google.com. 86400 IN CAA 0 issue "pki.goog"
google.com. 600 IN MX 50 alt4.aspmx.l.google.com.
google.com. 60 IN SOA ns1.google.com. dns-admin.google.com. 188478103 900 900 1800 60
google.com. 600 IN MX 10 aspmx.l.google.com.
google.com. 345600 IN NS ns2.google.com.
google.com. 345600 IN NS ns4.google.com.
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
