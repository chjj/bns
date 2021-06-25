# bns-prove

### Generate DNSSEC ownership proofs using local keys or hardware signing module (HSM).

_What is a DNSSEC ownership proof?_

The proof is a chain of DNSSEC keys and signatures starting with the root zone
(ICANN KSK2017) and ending with a signed TXT record in the target zone
([example](test/data/test-claim.proof)). To claim a reserved name in the
[Handshake blockchain network](https://handshake.org),
a cryptocurrency wallet address is encoded into a TXT record which is then signed
and passed to the network for decentralized verification of ownership.

Usage:

```
bns-prove [options] domain-name txt-string
```

To prove ownership of the domain name `example.com`, pass `bns-prove` the path
to the directory containing the zone signing key (ZSK). The private key must
exist in the specified directory in BIND’s private key format (v1.3)
([example](test/data/Khns-claim-test-2.xyz.+008+27259.private))

```
 $ bns-prove -b -K /path/to/DNSSEC/keys/ example.com hns-regtest:aakgpzi7wgivq75... 
```

### Options

`-x`: Output the proof formatted as a hex string (deprecated).

`-b`: Output the proof formatted as a base64 string (expected by [Handshake full node API](https://hsd-dev.org/api-docs/#sendrawclaim)).

`-s`: Do not upgrade insecure algorithms like `RSASHA1` or `RSASHA1NSEC3SHA1` if the signature
indicates a stronger algorithm (like `RSASHA256`).

`-r`: Do not allow weak keys like `RSA-1024`

`-t <number>`: Specify the expiration time in seconds for the RRSIG (default is one year).

`-K <string>`: Specify the directory containing the expected DNSSEC private key.

### HSM Mode Options

This software has been tested with
[SoftHSMv2](https://github.com/opendnssec/SoftHSMv2)
and should operate correctly with any device with a PKCS#11 interface.

`--hsm-module <string>`: Path to the HSM manufacturer's PKCS11 library.

`--hsm-slot <number>`: HSM slot where expected DNSSEC private key can be found.

`--hsm-pin <string>`: Normal user PIN for logging in to specified slot.