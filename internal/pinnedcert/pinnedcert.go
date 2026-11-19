// Package pinnedcert handles a malformed SAN on an explicitly pinned gateway.
// It does not weaken parsing of any other certificate or alter the signed DER.
package pinnedcert

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"
)

func Match(der []byte, fingerprint string) error {
	expected, err := hex.DecodeString(fingerprint)
	actual := sha256.Sum256(der)
	if err != nil || len(expected) != len(actual) || subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
		return errors.New("certificate fingerprint mismatch")
	}
	return nil
}

func Verify(fingerprint string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("certificate fingerprint missing")
		}
		return Match(raw[0], fingerprint)
	}
}

func Parse(der []byte, fingerprint string) (*x509.Certificate, error) {
	if err := Match(der, fingerprint); err != nil {
		return nil, err
	}
	cert, originalErr := x509.ParseCertificate(der)
	if originalErr == nil {
		return cert, nil
	}
	if !strings.Contains(originalErr.Error(), "SAN dNSName is malformed") {
		return nil, originalErr
	}
	outer, err := sequence(der)
	if err != nil || len(outer) != 3 {
		return nil, originalErr
	}
	tbs, err := sequence(outer[0].FullBytes)
	if err != nil {
		return nil, originalErr
	}
	originalTBS := append([]byte(nil), outer[0].FullBytes...)
	found := false
	var originalExtensions []pkix.Extension
	for i, value := range tbs {
		if value.Class != 2 || value.Tag != 3 {
			continue
		}
		var extensions []pkix.Extension
		rest, err := asn1.Unmarshal(value.Bytes, &extensions)
		if err != nil || len(rest) != 0 {
			return nil, originalErr
		}
		originalExtensions = append([]pkix.Extension(nil), extensions...)
		kept := make([]pkix.Extension, 0, len(extensions))
		for _, ext := range extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				found = true
				continue
			}
			kept = append(kept, ext)
		}
		encoded, err := asn1.Marshal(kept)
		if err != nil {
			return nil, err
		}
		tbs[i] = asn1.RawValue{Class: 2, Tag: 3, IsCompound: true, Bytes: encoded}
	}
	if !found {
		return nil, originalErr
	}
	newTBS, err := joinSequence(tbs)
	if err != nil {
		return nil, err
	}
	outer[0] = asn1.RawValue{FullBytes: newTBS}
	cleaned, err := joinSequence(outer)
	if err != nil {
		return nil, err
	}
	cert, err = x509.ParseCertificate(cleaned)
	if err != nil {
		return nil, err
	}
	cert.Raw = append([]byte(nil), der...)
	cert.RawTBSCertificate = originalTBS
	cert.Extensions = originalExtensions
	return cert, nil
}

func sequence(der []byte) ([]asn1.RawValue, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 || !outer.IsCompound {
		return nil, errors.New("invalid certificate sequence")
	}
	var result []asn1.RawValue
	for rest = outer.Bytes; len(rest) != 0; {
		var value asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &value)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func joinSequence(fields []asn1.RawValue) ([]byte, error) {
	var contents bytes.Buffer
	for _, field := range fields {
		encoded, err := asn1.Marshal(field)
		if err != nil {
			return nil, err
		}
		contents.Write(encoded)
	}
	return asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: contents.Bytes()})
}
