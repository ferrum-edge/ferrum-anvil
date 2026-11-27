# WS-Security X.509 XML signatures

Anvil's WS-Security auth profile (`"type": "wsse"`) inserts a `wsse:Security`
header into a SOAP 1.1 or 1.2 envelope at send time. It can carry a
UsernameToken (PasswordText or PasswordDigest), a `wsu:Timestamp`, a signed
SAML assertion you supply (embedded verbatim; Anvil never mints assertions)
and an X.509 XML signature (XML-DSig) made with your key. This page describes
the signature.

## What is signed and how

Every send signs afresh, so the Timestamp, the nonce and every element id are
new on each attempt, retry and load iteration.

- **References.** The SOAP `Body`, the `wsu:Timestamp` (when a Timestamp
  lifetime is set) and the `wsse:UsernameToken` (when one is sent), each by a
  same-document `#id` reference to its `wsu:Id`. The Body keeps its own
  `wsu:Id` if it has one; otherwise its start tag gains `wsu:Id` (and the
  `wsu` namespace declaration it needs, under another prefix if `wsu` is bound
  to something else there). Nothing else in your envelope changes.
- **Canonicalization.** Exclusive XML Canonicalization 1.0 without comments
  (`http://www.w3.org/2001/10/xml-exc-c14n#`) for `ds:SignedInfo` and as the
  one transform of every reference. An optional InclusiveNamespaces
  PrefixList (for QNames in content such as `xsi:type="t:Kind"`) is applied to
  every reference: a listed prefix is declared wherever it is in scope and
  not already in effect (Canonical XML's rule), as libxml2 and Ferrum Edge do.
- **Digests.** SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`).
- **Signature.** RSA PKCS#1 v1.5 with SHA-256
  (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`) for an RSA key, or
  ECDSA P-256 with SHA-256 (`...xmldsig-more#ecdsa-sha256`, the `r || s` form
  XML-DSig defines) for an EC key. SHA-1 is never used.
- **Key reference.** The certificate the key belongs to is sent as a
  `wsse:BinarySecurityToken` with the X.509 Token Profile `X509v3` value type,
  and `ds:KeyInfo` holds a `wsse:SecurityTokenReference` to it. Other
  certificates in the chain are not sent: an X509v3 token carries one
  certificate, and receivers such as Ferrum Edge trust the signing
  certificate itself.

The Security header holds, in order: Timestamp, UsernameToken, SAML
assertion, BinarySecurityToken, Signature. A UsernameToken can be turned off
(`username_token: false`) for a header that carries only a signature, a
Timestamp or an assertion.

## Keys and certificates

| Form | Fields |
| --- | --- |
| PEM | `cert_chain_pem` (certificates, not secret) and `private_key_pem`: PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) |
| PKCS#12 | `bundle_b64` (the `.p12`/`.pfx` bundle in base64) and its `password`; the first private key with a certificate is used |

Refused, each with its own message: RSA keys shorter than 2048 bits (or longer
than 8192), EC curves other than P-256, encrypted PEM keys (store the key
unencrypted in the vault, or use PKCS#12), a key that belongs to none of the
certificates, a private key pasted into the certificate field, and an
`algorithm` that does not suit the key. `algorithm` is `auto` (follow the
key), `rsa_sha256` or `ecdsa_p256_sha256`; a collection file naming any other
value, a SHA-1 one included, fails to load.

The private key, a PKCS#12 bundle and its password are sensitive values like
every other credential: in the desktop app they live in the workspace vault
(the editor's file buttons import a key or bundle straight into it), they are
registered for exact-value redaction of records, previews and logs, safe-share
exports replace literal values with placeholders, and only the existing
explicit secret-export path carries them. Error messages never quote key
material. Signing runs in AWS-LC (`aws-lc-rs`), which blinds RSA and uses
constant-time P-256 arithmetic.

## Desktop app

Request, folder or workspace auth → **WS-Security (UsernameToken, X.509
signature)** → **X.509 signature (XML-DSig)** → *Sign the Body, the Timestamp
and the UsernameToken*. Choose PEM or PKCS#12, load or paste the certificate,
put the key in the vault, and optionally pick the algorithm and a PrefixList.
Turning signing on sets a 300 s Timestamp if none is set.

## Collection files and the CLI

The CLI reads the same auth objects from collection and workspace files:

```json
{
  "type": "wsse",
  "config": {
    "username": "",
    "password": { "kind": "template", "value": "" },
    "username_token": false,
    "timestamp_ttl_secs": 300,
    "signature": {
      "identity": {
        "format": "pem",
        "cert_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
        "private_key_pem": { "kind": "template", "value": "{{WSSE_SIGNING_KEY}}" }
      },
      "algorithm": "auto",
      "inclusive_prefix_list": ""
    }
  }
}
```

A PKCS#12 identity is `{ "format": "pkcs12", "bundle_b64": …, "password": … }`.
Sensitive values take a `{{variable}}` (a secret variable or environment
value at run time) or a vault reference, as for any other credential.

## Verification

- `crates/anvil-auth/tests/c14n_vectors.rs`: the W3C Canonical XML examples
  that need no DTD and the Exclusive XML Canonicalization §2.2 example, plus
  PrefixList and default-namespace cases.
- `crates/anvil-auth/tests/wsse_signing.rs`: XML-DSig core validation of
  signed envelopes (RSA PKCS#8 and PKCS#1, ECDSA), tampering, key refusals,
  redaction registration.
- The `xmldsig-interop` workflow (`crates/anvil-auth/tests/xmldsig_interop.rs`):
  canonical forms equal libxml2's (`xmllint --exc-c14n`, and lxml's exclusive
  C14N for every element subtree with and without comments and with prefix
  lists; `#default`, which lxml cannot pass, through xmlsec1), and envelopes Anvil signs with OpenSSL-made RSA-2048/3072 and P-256
  keys verify with `xmlsec1`, which refuses them once the Body or the
  Timestamp changes.
- Lab scenario AUTH-030 ([lab/auth-tls.md](lab/auth-tls.md)): Ferrum Edge's
  `soap_ws_security` plugin accepts envelopes Anvil signs with the key its
  route trusts, and refuses an Anvil-signed Body altered after signing and a
  signature by an untrusted certificate. Ferrum Edge v0.9.21 verifies RSA
  signatures only, so ECDSA is verified by xmlsec1, not the Lab.
