// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spiffe

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"sort"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ParseBundleMap reads the standard SPIFFE Bundle Map. Only supported public
// X509-SVID authorities contribute roots, and only to their declared domain.
// An empty result is authoritative removal, not a request to restore defaults.
// Any malformed accepted key or duplicate decoded JSON key rejects the whole
// snapshot; callers must publish a denying context rather than retain old roots.
func ParseBundleMap(data []byte) (map[string][]byte, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	var doc struct {
		TrustDomains map[string]json.RawMessage `json:"trust_domains"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.TrustDomains == nil {
		return nil, fmt.Errorf("missing SPIFFE trust_domains object")
	}
	result := make(map[string][]byte, len(doc.TrustDomains))
	for name, raw := range doc.TrustDomains {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil || td.Name() != name || name == "" {
			return nil, fmt.Errorf("noncanonical SPIFFE trust domain %q", name)
		}
		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(raw, &jwks); err != nil {
			return nil, fmt.Errorf("invalid bundle for %s: %w", name, err)
		}
		if jwks.Keys == nil {
			return nil, fmt.Errorf("missing keys array for %s", name)
		}
		accepted := make([]json.RawMessage, 0, len(jwks.Keys))
		for _, rawKey := range jwks.Keys {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(rawKey, &fields); err != nil || fields == nil {
				return nil, fmt.Errorf("bundle key for %s must be an object", name)
			}
			var header struct {
				Use string `json:"use"`
				Kty string `json:"kty"`
				Crv string `json:"crv"`
			}
			if err := json.Unmarshal(rawKey, &header); err != nil {
				return nil, fmt.Errorf("invalid key for %s: %w", name, err)
			}
			// Unsupported standard uses/types confer no authority. Do not ask the
			// native decoder to turn an unsupported key into a supported anchor.
			if header.Use != "x509-svid" || (header.Kty != "RSA" && header.Kty != "EC") {
				continue
			}
			if header.Kty == "EC" && header.Crv != "P-256" && header.Crv != "P-384" && header.Crv != "P-521" {
				continue
			}
			if _, present := fields["kid"]; present {
				return nil, fmt.Errorf("X509-SVID key for %s must omit kid", name)
			}
			var key jose.JSONWebKey
			if err := json.Unmarshal(rawKey, &key); err != nil {
				return nil, fmt.Errorf("invalid X509-SVID key for %s: %w", name, err)
			}
			if !key.Valid() || !key.IsPublic() || len(key.Certificates) != 1 {
				return nil, fmt.Errorf("X509-SVID key for %s requires one public CA certificate", name)
			}
			cert := key.Certificates[0]
			if !cert.BasicConstraintsValid || !cert.IsCA || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
				return nil, fmt.Errorf("X509-SVID anchor for %s is not a signing CA", name)
			}
			accepted = append(accepted, rawKey)
		}
		// Native bundle parsing owns the certificate/JWK interpretation. Filtering
		// above implements the standard unsupported-key behavior for this profile.
		filtered, err := json.Marshal(struct {
			Keys []json.RawMessage `json:"keys"`
		}{Keys: accepted})
		if err != nil {
			return nil, err
		}
		bundle, err := spiffebundle.Parse(td, filtered)
		if err != nil {
			return nil, fmt.Errorf("invalid SPIFFE bundle for %s: %w", name, err)
		}
		certs := bundle.X509Authorities()
		sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i].Raw, certs[j].Raw) < 0 })
		for _, cert := range certs {
			result[name] = append(result[name], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
	}
	return result, nil
}

// encoding/json normally accepts duplicate keys, including differently escaped
// spellings of the same key. Walk native decoded tokens before unmarshalling.
func rejectDuplicateJSONKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]struct{}{}
			for d.More() {
				token, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok {
					return fmt.Errorf("invalid JSON object key")
				}
				if _, exists := keys[key]; exists {
					return fmt.Errorf("duplicate decoded JSON key %q", key)
				}
				keys[key] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON input: %v", err)
	}
	return nil
}
