/*
Copyright © 2023 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCompileCertificatesToPemBytes(t *testing.T) {
	// Generate two certificates for testing
	cert1, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate mock certificate: %v", err)
	}
	cert2, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate mock certificate: %v", err)
	}

	tests := []struct {
		name          string
		certificates  []*x509.Certificate
		expectedError bool
	}{
		{
			name:          "No certificates",
			certificates:  []*x509.Certificate{},
			expectedError: false,
		},
		{
			name:          "Single certificate",
			certificates:  []*x509.Certificate{cert1},
			expectedError: false,
		},
		{
			name:          "Multiple certificates",
			certificates:  []*x509.Certificate{cert1, cert2},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = CompileCertificatesToPemBytes(tt.certificates)
			if (err != nil) != tt.expectedError {
				t.Errorf("expected error = %v, got %v", tt.expectedError, err)
			}
		})
	}
}

func generateSelfSignedCertificate() (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
