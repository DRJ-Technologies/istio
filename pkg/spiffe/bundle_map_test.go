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
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"istio.io/istio/pkg/testcerts"
)

func TestParseBundleMapNativeAuthorityAndRemoval(t *testing.T) {
	block, _ := pem.Decode(testcerts.CACert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	td, err := spiffeid.TrustDomainFromString("local.example")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := spiffebundle.FromX509Authorities(td, []*x509.Certificate{cert}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"trust_domains": map[string]json.RawMessage{
		"local.example":       bundle,
		"removed.example":     json.RawMessage(`{"keys":[]}`),
		"unsupported.example": json.RawMessage(`{"keys":[{"use":"jwt-svid","kty":"RSA"},{"use":"x509-svid","kty":"OKP"}]}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBundleMap(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("unexpected domain authority: %v", got)
	}
	anchor, rest := pem.Decode(got["local.example"])
	if anchor == nil || len(rest) != 0 || !bytes.Equal(anchor.Bytes, cert.Raw) {
		t.Fatal("native certificate did not survive domain-preserving parse")
	}
	for _, input := range []string{`{"trust_domains":{}}`, `{"trust_domains":{"local.example":{"keys":[]}}}`} {
		roots, err := ParseBundleMap([]byte(input))
		if err != nil || roots == nil || len(roots) != 0 {
			t.Fatalf("empty authority must be a nonnil complete removal: %v %v", roots, err)
		}
	}
}

func TestParseBundleMapRefusesDecodedDuplicateKeysAndMalformedInput(t *testing.T) {
	for _, input := range []string{
		`{"trust_domains":{},"\u0074rust_domains":{}}`,
		`{"trust_domains":{"a.example":{"keys":[]},"a.\u0065xample":{"keys":[]}}}`,
		`{"trust_domains":{"a.example":{"keys":[],"\u006beys":[]}}}`,
		`{"trust_domains":{"a.example":{"keys":[{"use":"x509-svid","\u0075se":"jwt-svid"}]}}}`,
		`{"trust_domains":{"a.example":{"keys":[{"ignored":{"x":1,"\u0078":2}}]}}}`,
		`{"trust_domains":{}} {"trust_domains":{}}`,
		`null`, `[]`, `{}`, `{"trust_domains":null}`,
		`{"trust_domains":{"spiffe://a.example":{"keys":[]}}}`,
		`{"trust_domains":{"A.example":{"keys":[]}}}`,
		`{"trust_domains":{"a.example":{}}}`,
		`{"trust_domains":{"a.example":{"keys":null}}}`,
		`{"trust_domains":{"a.example":{"keys":[null]}}}`,
		`{"trust_domains":{"a.example":{"keys":[{"use":"x509-svid","kty":"RSA","kid":""}]}}}`,
		`{"trust_domains":{"a.example":{"keys":[{"use":"x509-svid","kty":"RSA","x5c":[]}]}}}`,
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := ParseBundleMap([]byte(input)); err == nil || got != nil {
				t.Fatal("malformed snapshot retained partial or ambiguous authority")
			}
		})
	}
}
