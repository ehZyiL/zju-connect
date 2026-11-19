Upstream: github.com/refraction-networking/utls v1.8.2 (BSD-3-Clause; see LICENSE).
Runtime sources copied from the Go module cache. Examples, upstream tests and
testdata are omitted.

Patch: common.go adds Config.ParsePeerCertificate and clones it. In
handshake_client.go it is called only after standard parsing fails and only
with InsecureSkipVerify. Fallback results never enter the global cache.

The application callback requires an exact SHA256 pin and only tolerates the
malformed SAN DNS-name error. It removes SAN from a temporary parse copy then
restores original signed bytes. The leaf pin is checked on every handshake,
including normally parseable certificates. No standard-library overlay is used.

Tests for the policy and actual TLS handshake live in internal/pinnedcert.
