/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const smimea = require('../lib/smimea');
const {usages, selectors, matchingTypes} = smimea;

function fromBase64(str) {
  return Buffer.from(str.replace(/\s+/g, ''), 'base64');
}

describe('S/MIMEA', function() {
  it('should serialize email', () => {
    const name1 = smimea.encodeEmail('slippinjimmy@example.com.', 256);

    assert.strictEqual(name1,
      'ae91629c1142f97683521f4b70cade48e95202aff15c16f0fdf34779'
      + '._smimecert.example.com.');

    const name2 = smimea.encodeEmail('slippinjimmy@example.com.', 224);

    assert.strictEqual(name2,
      'b33f5890ccb3ea7d9c91a6459d75a8a27eb9e894ab25fd2b5fc26aef'
      + '._smimecert.example.com.');

    assert(smimea.isName(name1));
    assert(smimea.isName(name2));

    const data1 = smimea.decodeName(name1);
    assert.strictEqual(data1.name, 'example.com.');
    assert.strictEqual(data1.hash.length, 28);

    const data2 = smimea.decodeName(name1);
    assert.strictEqual(data2.name, 'example.com.');
    assert.strictEqual(data2.hash.length, 28);
  });

  it('should create SMIMEA record', () => {
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

    const rr = smimea.create(cert, 'slippinjimmy@example.com.', {
      ttl: 3600,
      usage: usages.DIC,
      selector: selectors.SPKI,
      matchingType: matchingTypes.SHA256
    });

    assert(smimea.verify(rr, cert));

    const rr2 = smimea.create(cert, 'slippinjimmy@example.com.', {
      ttl: 3600,
      usage: usages.DIC,
      selector: selectors.FULL,
      matchingType: matchingTypes.SHA256
    });

    assert(smimea.verify(rr2, cert));

    cert[30] ^= 1;

    assert(!smimea.verify(rr2, cert));
  });
});
