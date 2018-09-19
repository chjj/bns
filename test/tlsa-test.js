/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const dns = require('../lib/dns');
const tlsa = require('../lib/tlsa');
const wire = require('../lib/wire');
const {usages, selectors, matchingTypes} = tlsa;
const {Record} = wire;

function fromBase64(str) {
  return Buffer.from(str.replace(/\s+/g, ''), 'base64');
}

describe('TLSA', function() {
  it('should serialize name', () => {
    const name = tlsa.encodeName('example.com', 'tcp', 443);

    assert.strictEqual(name, '_443._tcp.example.com.');
    assert(tlsa.isName(name));
    assert(!tlsa.isName('example.com.'));

    const data = tlsa.decodeName(name);

    assert.strictEqual(data.name, 'example.com.');
    assert.strictEqual(data.protocol, 'tcp');
    assert.strictEqual(data.port, 443);
  });

  it('should verify spki+sha256 cert (www.ietf.org)', () => {
    // $ dig.js _443._tcp.www.ietf.org. TLSA
    const str = '_443._tcp.www.ietf.org. 1500 IN TLSA'
      + ' 3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B566'
      + ' 64C5D3D6';
    const rr = Record.fromString(str);

    // $ openssl s_client -showcerts -connect www.ietf.org:443 < /dev/null
    const cert = fromBase64(`
      MIIFUTCCBDmgAwIBAgIIITAshaEP0OswDQYJKoZIhvcNAQELBQAwgcYxCzAJBgNV
      BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUw
      IwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTMwMQYDVQQLEypo
      dHRwOi8vY2VydHMuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8xNDAyBgNV
      BAMTK1N0YXJmaWVsZCBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIw
      HhcNMTcwNjEyMTAxMjAwWhcNMTgwODExMjMxMjUwWjA4MSEwHwYDVQQLExhEb21h
      aW4gQ29udHJvbCBWYWxpZGF0ZWQxEzARBgNVBAMMCiouaWV0Zi5vcmcwggEiMA0G
      CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2eMubW2zWELh8023dSdAP3LvdsNeC
      KhPJZhIjdxr8o1+5PJ2MVMRgCaqe4asE5R+BuYfc9FDQCamqWOBZNvd3crwfhQW8
      NZBM9JLbUgyObyip3X2cTkbFaKsa7SgNHOFYsd7VFntmuiEI+D/U5yzLjtBm4raV
      oUHSsSatFYGYRhsOXf/DF/ld+oiqk7KckHTa2FetMJxMztHPUWoIW39lVkHmEpjZ
      L4JN0T04hUqWvhYcx+69Rh46PToaTAsUkc2/a1T62i8jeZhHFS5jhS6mRLcwL461
      7LtcqbU/4g2NZah6CbqIIC3dW6ylXP7qlTbGCXeesBUxAcHh9F5A8fSlAgMBAAGj
      ggHOMIIByjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
      BQcDAjAOBgNVHQ8BAf8EBAMCBaAwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2Ny
      bC5zdGFyZmllbGR0ZWNoLmNvbS9zZmlnMnMxLTU2LmNybDBjBgNVHSAEXDBaME4G
      C2CGSAGG/W4BBxcBMD8wPQYIKwYBBQUHAgEWMWh0dHA6Ly9jZXJ0aWZpY2F0ZXMu
      c3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQIBMIGGBggrBgEF
      BQcBAQR6MHgwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnN0YXJmaWVsZHRlY2gu
      Y29tLzBKBggrBgEFBQcwAoY+aHR0cDovL2NlcnRpZmljYXRlcy5zdGFyZmllbGR0
      ZWNoLmNvbS9yZXBvc2l0b3J5L3NmaWcyLmNydC5kZXIwHwYDVR0jBBgwFoAUJUWB
      aFAmOD07LSy+zWrZtj2zZmMwHwYDVR0RBBgwFoIKKi5pZXRmLm9yZ4IIaWV0Zi5v
      cmcwHQYDVR0OBBYEFAb+C6vY5nRu/MRzAoX3qUh+0TRPMA0GCSqGSIb3DQEBCwUA
      A4IBAQDkjdd7Mz2F83bfBNjAS0uN0mGIn2Z67dcWP+klzp7JzGb+qdbPZsI0aHKZ
      UEh0Pl71hcn8LlhYl+n7GJUGhW7CaOVqhzHkxfyfIls6BJ+pL6mIx5be8xqSV04b
      zyPBZcPnuFdi/dXAgjE9iSFHfNH8gthiXgzgiIPIjQp2xuJDeQHWT5ZQ5gUxF8qP
      ecO5L6IwMzZFRuE6SYzFynsOMOGjsPYJkYLm3JYwUulDz7OtRABwN5wegc5tTgq5
      9HaFOULLCdMakLIRmMC0PzSI+m3+cYoZ6ue/8q9my7HgekcVMYQ5lRKncrs3GMxo
      WNyYOpbGqBfooA8nwwE20fpacX2i
    `);

    assert(tlsa.verify(rr, cert));
  });

  it('should verify spki+sha256 cert (www.huque.com)', () => {
    // $ dig.js _443._tcp.www.huque.com. TLSA
    const str = '_443._tcp.www.huque.com. 4270 IN TLSA'
      + ' 3 1 1 F6D8BB3FD6B09E73EBFC347F8F34E7ABB6AFB31105AE20ACEC4F1F57'
      + ' 63FE7FC1';
    const rr = Record.fromString(str);

    // $ openssl s_client -showcerts -connect www.huque.com:443 < /dev/null
    const cert = fromBase64(`
      MIIE/TCCA+WgAwIBAgISA+XMxBpZ8QPRypKtzNXcAMCuMA0GCSqGSIb3DQEBCwUA
      MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
      ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODAxMTkwMDMwMjFaFw0x
      ODA0MTkwMDMwMjFaMBgxFjAUBgNVBAMTDXd3dy5odXF1ZS5jb20wggEiMA0GCSqG
      SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiDkfG6zL1hkc64yKAY/IrzQYemhJkyl+G
      i8WAL6BiP18z1vleCN/HMkApddgkWCV2xEbHQC6hExxWs5h27d9BfC4bRKbXVWzH
      wDW1ciaMAKRMibLUSyKcUu9/C+bJRJMtfLN8+Zmsh2ftrArvkiy3VfdhZQJ7ZH9q
      kAqSAKn/4IVTsxwzCjNGPpjxSy1S/CTuKfoydOdoJBc6e5qPV7CQNjSdI/I/24VB
      2ckhAb+X7sF88Pcy3JDfSMMnYEOaAKsaKJfr6SPsHcVdHqn43Bjqui3+m+tTQwgO
      wmnCWc/scJ5M5zZEWkMatcVgmSSdpLU1uEP1qoqT4TK+c8NcbrH/AgMBAAGjggIN
      MIICCTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
      BwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNLptiUj9iGzhrPB/sj2CJP++46y
      MB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMw
      YTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9y
      ZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9y
      Zy8wGAYDVR0RBBEwD4INd3d3Lmh1cXVlLmNvbTCB/gYDVR0gBIH2MIHzMAgGBmeB
      DAECATCB5gYLKwYBBAGC3xMBAQEwgdYwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMu
      bGV0c2VuY3J5cHQub3JnMIGrBggrBgEFBQcCAjCBngyBm1RoaXMgQ2VydGlmaWNh
      dGUgbWF5IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQYXJ0aWVzIGFu
      ZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9saWN5
      IGZvdW5kIGF0IGh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL3JlcG9zaXRvcnkvMA0G
      CSqGSIb3DQEBCwUAA4IBAQBvBaLlfwTLwVWyEbMzXS6Parm0BR0Sp+EwGT4NHXj7
      x/ofVThcocSS/o4cRApeB1P6gVyHazCq0fVmaYlB8LeS7lfDr/DO8mlGpNGL7rQ5
      rAx/ZAK28FB6N2+kVkEB6cOTa3+YfNfY+x35BO1SpHtwP9WZPCjuLQVG2nXEwoMR
      MK0l+JJx2fw6dzScDjzKRn8jqCzi7rrqCycHwuFwSFEd1VqJXGuLOymVg1XzcVTM
      FhCadti+z6LFapAgGP68HdOdv4VRLITjpe/8vmYhPZa+/G1fDjsweU5fUBiy1OWS
      y/6AZMy11PrBQJ1Ogz6SxgwQkARCvgkgXRTjDKUUvDpH
    `);

    assert(tlsa.verify(rr, cert));
  });

  it('should verify full+sha256+cac cert (fedoraproject.org)', () => {
    // $ dig.js _443._tcp.fedoraproject.org TLSA
    const str = '_443._tcp.fedoraproject.org. 300 IN TLSA'
      + ' 0 0 1 19400BE5B7A31FB733917700789D2F0A2471C0C9D506C0E504C06C16'
      + ' D7CB17C0';

    const rr = Record.fromString(str);

    // $ openssl s_client -showcerts -connect fedoraproject.org:443 < /dev/null
    const cert = fromBase64(`
      MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs
      MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
      d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
      ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL
      MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
      LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy
      YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2
      4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC
      Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1
      itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn
      4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X
      sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft
      bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA
      MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
      NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
      dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t
      L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG
      BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
      UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D
      aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd
      aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH
      E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly
      /D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu
      xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF
      0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae
      cPUeybQ=
    `);

    assert(tlsa.verify(rr, cert));
  });

  it('should verify spki+sha256 cert (www.ietf.org)', async () => {
    const cert = fromBase64(`
      MIIFUTCCBDmgAwIBAgIIITAshaEP0OswDQYJKoZIhvcNAQELBQAwgcYxCzAJBgNV
      BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUw
      IwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTMwMQYDVQQLEypo
      dHRwOi8vY2VydHMuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8xNDAyBgNV
      BAMTK1N0YXJmaWVsZCBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIw
      HhcNMTcwNjEyMTAxMjAwWhcNMTgwODExMjMxMjUwWjA4MSEwHwYDVQQLExhEb21h
      aW4gQ29udHJvbCBWYWxpZGF0ZWQxEzARBgNVBAMMCiouaWV0Zi5vcmcwggEiMA0G
      CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2eMubW2zWELh8023dSdAP3LvdsNeC
      KhPJZhIjdxr8o1+5PJ2MVMRgCaqe4asE5R+BuYfc9FDQCamqWOBZNvd3crwfhQW8
      NZBM9JLbUgyObyip3X2cTkbFaKsa7SgNHOFYsd7VFntmuiEI+D/U5yzLjtBm4raV
      oUHSsSatFYGYRhsOXf/DF/ld+oiqk7KckHTa2FetMJxMztHPUWoIW39lVkHmEpjZ
      L4JN0T04hUqWvhYcx+69Rh46PToaTAsUkc2/a1T62i8jeZhHFS5jhS6mRLcwL461
      7LtcqbU/4g2NZah6CbqIIC3dW6ylXP7qlTbGCXeesBUxAcHh9F5A8fSlAgMBAAGj
      ggHOMIIByjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
      BQcDAjAOBgNVHQ8BAf8EBAMCBaAwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2Ny
      bC5zdGFyZmllbGR0ZWNoLmNvbS9zZmlnMnMxLTU2LmNybDBjBgNVHSAEXDBaME4G
      C2CGSAGG/W4BBxcBMD8wPQYIKwYBBQUHAgEWMWh0dHA6Ly9jZXJ0aWZpY2F0ZXMu
      c3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQIBMIGGBggrBgEF
      BQcBAQR6MHgwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnN0YXJmaWVsZHRlY2gu
      Y29tLzBKBggrBgEFBQcwAoY+aHR0cDovL2NlcnRpZmljYXRlcy5zdGFyZmllbGR0
      ZWNoLmNvbS9yZXBvc2l0b3J5L3NmaWcyLmNydC5kZXIwHwYDVR0jBBgwFoAUJUWB
      aFAmOD07LSy+zWrZtj2zZmMwHwYDVR0RBBgwFoIKKi5pZXRmLm9yZ4IIaWV0Zi5v
      cmcwHQYDVR0OBBYEFAb+C6vY5nRu/MRzAoX3qUh+0TRPMA0GCSqGSIb3DQEBCwUA
      A4IBAQDkjdd7Mz2F83bfBNjAS0uN0mGIn2Z67dcWP+klzp7JzGb+qdbPZsI0aHKZ
      UEh0Pl71hcn8LlhYl+n7GJUGhW7CaOVqhzHkxfyfIls6BJ+pL6mIx5be8xqSV04b
      zyPBZcPnuFdi/dXAgjE9iSFHfNH8gthiXgzgiIPIjQp2xuJDeQHWT5ZQ5gUxF8qP
      ecO5L6IwMzZFRuE6SYzFynsOMOGjsPYJkYLm3JYwUulDz7OtRABwN5wegc5tTgq5
      9HaFOULLCdMakLIRmMC0PzSI+m3+cYoZ6ue/8q9my7HgekcVMYQ5lRKncrs3GMxo
      WNyYOpbGqBfooA8nwwE20fpacX2i
    `);

    // Hack for testing.
    dns._allowInsecure = true;

    const rrs = await dns.resolveTLSA('www.ietf.org', 'tcp', 443);

    assert(Array.isArray(rrs));
    assert(rrs.length >= 1);

    let valid = false;

    for (const rr of rrs) {
      if (dns.verifyTLSA(rr, cert)) {
        valid = true;
        break;
      }
    }

    assert(valid);
  });

  it('should create TLSA record', () => {
    // $ openssl s_client -showcerts -connect www.ietf.org:443 < /dev/null
    const cert = fromBase64(`
      MIIFUTCCBDmgAwIBAgIIITAshaEP0OswDQYJKoZIhvcNAQELBQAwgcYxCzAJBgNV
      BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUw
      IwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTMwMQYDVQQLEypo
      dHRwOi8vY2VydHMuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8xNDAyBgNV
      BAMTK1N0YXJmaWVsZCBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIw
      HhcNMTcwNjEyMTAxMjAwWhcNMTgwODExMjMxMjUwWjA4MSEwHwYDVQQLExhEb21h
      aW4gQ29udHJvbCBWYWxpZGF0ZWQxEzARBgNVBAMMCiouaWV0Zi5vcmcwggEiMA0G
      CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2eMubW2zWELh8023dSdAP3LvdsNeC
      KhPJZhIjdxr8o1+5PJ2MVMRgCaqe4asE5R+BuYfc9FDQCamqWOBZNvd3crwfhQW8
      NZBM9JLbUgyObyip3X2cTkbFaKsa7SgNHOFYsd7VFntmuiEI+D/U5yzLjtBm4raV
      oUHSsSatFYGYRhsOXf/DF/ld+oiqk7KckHTa2FetMJxMztHPUWoIW39lVkHmEpjZ
      L4JN0T04hUqWvhYcx+69Rh46PToaTAsUkc2/a1T62i8jeZhHFS5jhS6mRLcwL461
      7LtcqbU/4g2NZah6CbqIIC3dW6ylXP7qlTbGCXeesBUxAcHh9F5A8fSlAgMBAAGj
      ggHOMIIByjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
      BQcDAjAOBgNVHQ8BAf8EBAMCBaAwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2Ny
      bC5zdGFyZmllbGR0ZWNoLmNvbS9zZmlnMnMxLTU2LmNybDBjBgNVHSAEXDBaME4G
      C2CGSAGG/W4BBxcBMD8wPQYIKwYBBQUHAgEWMWh0dHA6Ly9jZXJ0aWZpY2F0ZXMu
      c3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQIBMIGGBggrBgEF
      BQcBAQR6MHgwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnN0YXJmaWVsZHRlY2gu
      Y29tLzBKBggrBgEFBQcwAoY+aHR0cDovL2NlcnRpZmljYXRlcy5zdGFyZmllbGR0
      ZWNoLmNvbS9yZXBvc2l0b3J5L3NmaWcyLmNydC5kZXIwHwYDVR0jBBgwFoAUJUWB
      aFAmOD07LSy+zWrZtj2zZmMwHwYDVR0RBBgwFoIKKi5pZXRmLm9yZ4IIaWV0Zi5v
      cmcwHQYDVR0OBBYEFAb+C6vY5nRu/MRzAoX3qUh+0TRPMA0GCSqGSIb3DQEBCwUA
      A4IBAQDkjdd7Mz2F83bfBNjAS0uN0mGIn2Z67dcWP+klzp7JzGb+qdbPZsI0aHKZ
      UEh0Pl71hcn8LlhYl+n7GJUGhW7CaOVqhzHkxfyfIls6BJ+pL6mIx5be8xqSV04b
      zyPBZcPnuFdi/dXAgjE9iSFHfNH8gthiXgzgiIPIjQp2xuJDeQHWT5ZQ5gUxF8qP
      ecO5L6IwMzZFRuE6SYzFynsOMOGjsPYJkYLm3JYwUulDz7OtRABwN5wegc5tTgq5
      9HaFOULLCdMakLIRmMC0PzSI+m3+cYoZ6ue/8q9my7HgekcVMYQ5lRKncrs3GMxo
      WNyYOpbGqBfooA8nwwE20fpacX2i
    `);

    const rr = tlsa.create(cert, 'www.ietf.org', 'tcp', 443, {
      ttl: 3600,
      usage: usages.DIC,
      selector: selectors.SPKI,
      matchingType: matchingTypes.SHA256
    });

    assert(tlsa.verify(rr, cert));

    const rr2 = tlsa.create(cert, 'www.ietf.org', 'tcp', 443, {
      ttl: 3600,
      usage: usages.DIC,
      selector: selectors.FULL,
      matchingType: matchingTypes.SHA256
    });

    assert(tlsa.verify(rr2, cert));

    cert[30] ^= 1;

    assert(!tlsa.verify(rr2, cert));
  });
});
