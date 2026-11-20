Upstream: github.com/refraction-networking/utls v1.8.2 (BSD-3-Clause; see LICENSE).
Runtime sources copied from the Go module cache. Examples, upstream tests and
testdata are omitted.

Patch: common.go adds Config.ParsePeerCertificate and clones it. In
handshake_client.go it is called only after standard parsing fails and only
with InsecureSkipVerify. Fallback results never enter the global cache.

The login callback requires an explicitly saved, exact SHA256 pin and only
tolerates the malformed SAN DNS-name error. It removes SAN from a temporary
parse copy then restores original signed bytes. The leaf pin is checked on every
login/tunnel handshake, including normally parseable certificates. No
standard-library overlay is used.

The separate certificate_probe desktop command also uses this parser, with a
hash calculated from the observed DER, only to display an untrusted certificate
for user review. This connection completes a TLS handshake and closes without
sending HTTP, credentials or a client certificate. It cannot start a VPN or save
trust. The GUI requires explicit confirmation before saving the observed hash;
later logins still enforce the saved pin. Observation is not identity validation.

Tests for the policy and actual TLS handshake live in internal/pinnedcert.
