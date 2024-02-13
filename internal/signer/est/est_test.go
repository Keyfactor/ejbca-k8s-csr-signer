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

package est

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	logrtesting "github.com/go-logr/logr/testr"
	"go.mozilla.org/pkcs7"
	ctrl "sigs.k8s.io/controller-runtime"
)

func TestClient_SimpleEnrollSuccess(t *testing.T) {
	username := "user"
	password := "password"
	estAlias := "testAlias"

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %s", err.Error())
	}

	simpleEnrollResponder := func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Request: %v", r)

		if r.URL.Path != fmt.Sprintf("/.well-known/est/%s/simpleenroll", estAlias) {
			t.Fatalf("Expected URL path to be /.well-known/%s/est/simpleenroll, got %s", estAlias, r.URL.Path)
		}

		if r.Header.Get("Content-Type") != "application/pkcs10" {
			t.Fatalf("Expected Content-Type to be application/pkcs10, got %s", r.Header.Get("Content-Type"))
		}

		if r.Header.Get("Content-Transfer-Encoding") != "base64" {
			t.Fatalf("Expected Content-Transfer-Encoding to be base64, got %s", r.Header.Get("Content-Transfer-Encoding"))
		}

		b64AuthString := r.Header.Get("Authorization")
		authString, err := base64.StdEncoding.DecodeString(b64AuthString[6:])
		if err != nil {
			t.Fatalf("Failed to decode base64 auth string: %s", err.Error())
		}

		if string(authString) != fmt.Sprintf("%s:%s", username, password) {
			t.Fatalf("Expected Authorization header to be %s:%s, got %s", username, password, string(authString))
		}

		t.Logf("SimpleEnroll request validated successfully")

		b64Pkcs7 := exportCertificateToB64Pkcs7(cert)

		w.Header().Set("Content-Type", "application/pkcs7-mime")
		w.Header().Set("Content-Transfer-Encoding", "base64")
		w.WriteHeader(200)
		_, err = w.Write(b64Pkcs7)
        if err != nil {
            t.Fatalf("Failed to write response: %v", err)
        }
	}

	testServer := httptest.NewTLSServer(http.HandlerFunc(simpleEnrollResponder))
	defer testServer.Close()

	ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))

	client, err := NewBuilder(testServer.URL).
		WithContext(ctx).
		WithClient(http.DefaultClient).
		WithCaCertificates([]*x509.Certificate{testServer.Certificate()}).
		WithBasicAuth(username, password).
		WithDefaultESTAlias(estAlias).
		Build()
	if err != nil {
		t.Fatalf("failed to create client: %s", err.Error())
	}

	csr, _, err := generateCSR("CN=test.com", []string{}, []string{}, []string{})
    if err != nil {
        t.Fatalf("failed to generate CSR: %s", err.Error())
    }

	certs, err := client.SimpleEnroll(estAlias, string(csr))
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected SimpleEnroll to return exactly 1 certificate - got back %d", len(certs))
	}

	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("Expected CommonName to be %s, got %s", cert.Subject.CommonName, certs[0].Subject.CommonName)
	}

	if certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("Expected SerialNumber to be %s, got %s", cert.SerialNumber, certs[0].SerialNumber)
	}
}

func TestClient_SimpleEnrollNoAliasSuccess(t *testing.T) {
	username := "user"
	password := "password"

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %s", err.Error())
	}

	simpleEnrollResponder := func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Request: %v", r)

		if r.URL.Path != "/.well-known/est/simpleenroll" {
            t.Fatalf("Expected URL path to be /.well-known/est/simpleenroll, got %s", r.URL.Path)
		}

		if r.Header.Get("Content-Type") != "application/pkcs10" {
			t.Fatalf("Expected Content-Type to be application/pkcs10, got %s", r.Header.Get("Content-Type"))
		}

		if r.Header.Get("Content-Transfer-Encoding") != "base64" {
			t.Fatalf("Expected Content-Transfer-Encoding to be base64, got %s", r.Header.Get("Content-Transfer-Encoding"))
		}

		b64AuthString := r.Header.Get("Authorization")
		authString, err := base64.StdEncoding.DecodeString(b64AuthString[6:])
		if err != nil {
			t.Fatalf("Failed to decode base64 auth string: %s", err.Error())
		}

		if string(authString) != fmt.Sprintf("%s:%s", username, password) {
			t.Fatalf("Expected Authorization header to be %s:%s, got %s", username, password, string(authString))
		}

		t.Logf("SimpleEnroll request validated successfully")

		b64Pkcs7 := exportCertificateToB64Pkcs7(cert)

		w.Header().Set("Content-Type", "application/pkcs7-mime")
		w.Header().Set("Content-Transfer-Encoding", "base64")
		w.WriteHeader(200)
		_, err = w.Write(b64Pkcs7)
        if err != nil {
            t.Fatalf("Failed to write response: %v", err)
        }
	}

	testServer := httptest.NewTLSServer(http.HandlerFunc(simpleEnrollResponder))
	defer testServer.Close()

	ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))

	client, err := NewBuilder(testServer.URL).
		WithContext(ctx).
		WithClient(http.DefaultClient).
		WithCaCertificates([]*x509.Certificate{testServer.Certificate()}).
		WithBasicAuth(username, password).
		Build()
	if err != nil {
		t.Fatalf("failed to create client: %s", err.Error())
	}

	csr, _, err := generateCSR("CN=test.com", []string{}, []string{}, []string{})
    if err != nil {
        t.Fatalf("failed to generate CSR: %s", err.Error())
    }

	certs, err := client.SimpleEnroll("", string(csr))
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected SimpleEnroll to return exactly 1 certificate - got back %d", len(certs))
	}

	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("Expected CommonName to be %s, got %s", cert.Subject.CommonName, certs[0].Subject.CommonName)
	}

	if certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("Expected SerialNumber to be %s, got %s", cert.SerialNumber, certs[0].SerialNumber)
	}
}

func TestClient_SimpleEnrollFailure(t *testing.T) {
	username := "user"
	password := "password"
	estAlias := "testAlias"

    testCases := []struct {
        name string
        handlerFunc func(w http.ResponseWriter, r *http.Request)
        expectedError error
    }{
        {
            name: "InvalidContentType",
            handlerFunc: func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(200)
            },
            expectedError: fmt.Errorf("unexpected content-type: application/json"),
        },
        {
            name: "InvalidContentTransferEncoding",
            handlerFunc: func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/pkcs7-mime")
                w.Header().Set("Content-Transfer-Encoding", "binary")
                w.WriteHeader(200)
            },
            expectedError: fmt.Errorf("unexpected content-transfer-encoding: binary"),
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            testServer := httptest.NewTLSServer(http.HandlerFunc(tc.handlerFunc))
            defer testServer.Close()

            ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))

            client, err := NewBuilder(testServer.URL).
                WithContext(ctx).
                WithClient(http.DefaultClient).
                WithCaCertificates([]*x509.Certificate{testServer.Certificate()}).
                WithBasicAuth(username, password).
                WithDefaultESTAlias(estAlias).
                Build()
            if err != nil {
                t.Fatalf("failed to create client: %s", err.Error())
            }

            csr, _, err := generateCSR("CN=test.com", []string{}, []string{}, []string{})
            if err != nil {
                t.Fatalf("failed to generate CSR: %s", err.Error())
            }

            _, err = client.SimpleEnroll(estAlias, string(csr))
            if err == nil {
                t.Fatal("Expected SimpleEnroll to return an error")
            }

            if err.Error() != tc.expectedError.Error() {
                t.Fatalf("Expected error to be %q, got %q", tc.expectedError.Error(), err.Error())
            }
        })
    }
}

func TestClient_CaCertsSuccess(t *testing.T) {
	estAlias := "testAlias"

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %s", err.Error())
	}

	caCertsResponder := func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Request: %v", r)

		if r.URL.Path != fmt.Sprintf("/.well-known/est/%s/cacerts", estAlias) {
			t.Fatalf("Expected URL path to be /.well-known/%s/est/cacerts, got %s", estAlias, r.URL.Path)
		}

		t.Logf("CaCerts request validated successfully")

		b64Pkcs7 := exportCertificateToB64Pkcs7(cert)

		w.Header().Set("Content-Type", "application/pkcs7-mime")
		w.Header().Set("Content-Transfer-Encoding", "base64")
		w.WriteHeader(200)
		_, err = w.Write(b64Pkcs7)
        if err != nil {
            t.Fatalf("Failed to write response: %v", err)
        }
	}

	testServer := httptest.NewTLSServer(http.HandlerFunc(caCertsResponder))
	defer testServer.Close()

	ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))

	client, err := NewBuilder(testServer.URL).
		WithContext(ctx).
		WithClient(http.DefaultClient).
		WithCaCertificates([]*x509.Certificate{testServer.Certificate()}).
		WithDefaultESTAlias(estAlias).
		Build()
	if err != nil {
		t.Fatalf("failed to create client: %s", err.Error())
	}

	certs, err := client.CaCerts(estAlias)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected CaCerts to return exactly 1 certificate - got back %d", len(certs))
	}

	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("Expected CommonName to be %s, got %s", cert.Subject.CommonName, certs[0].Subject.CommonName)
	}

	if certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("Expected SerialNumber to be %s, got %s", cert.SerialNumber, certs[0].SerialNumber)
	}
}

func TestClient_CaCertsNoAliasSuccess(t *testing.T) {
	cert, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %s", err.Error())
	}

	caCertsResponder := func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Request: %v", r)

        if r.URL.Path != "/.well-known/est/cacerts" {
            t.Fatalf("Expected URL path to be /.well-known/est/cacerts, got %s", r.URL.Path)
        }

		t.Logf("CaCerts request validated successfully")

		b64Pkcs7 := exportCertificateToB64Pkcs7(cert)

		w.Header().Set("Content-Type", "application/pkcs7-mime")
		w.Header().Set("Content-Transfer-Encoding", "base64")
		w.WriteHeader(200)
		_, err = w.Write(b64Pkcs7)
        if err != nil {
            t.Fatalf("Failed to write response: %v", err)
        }
	}

	testServer := httptest.NewTLSServer(http.HandlerFunc(caCertsResponder))
	defer testServer.Close()

	ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))

	client, err := NewBuilder(testServer.URL).
		WithContext(ctx).
		WithClient(http.DefaultClient).
		WithCaCertificates([]*x509.Certificate{testServer.Certificate()}).
		Build()
	if err != nil {
		t.Fatalf("failed to create client: %s", err.Error())
	}

	certs, err := client.CaCerts("")
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected CaCerts to return exactly 1 certificate - got back %d", len(certs))
	}

	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("Expected CommonName to be %s, got %s", cert.Subject.CommonName, certs[0].Subject.CommonName)
	}

	if certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("Expected SerialNumber to be %s, got %s", cert.SerialNumber, certs[0].SerialNumber)
	}
}

func TestClient_CaCertsFailure(t *testing.T) {
	estAlias := "testAlias"

    testCases := []struct {
        name string
        handlerFunc func(w http.ResponseWriter, r *http.Request)
        expectedError error
    }{
        {
            name: "InvalidContentType",
            handlerFunc: func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(200)
            },
            expectedError: fmt.Errorf("unexpected content-type: application/json"),
        },
        {
            name: "InvalidContentTransferEncoding",
            handlerFunc: func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/pkcs7-mime")
                w.Header().Set("Content-Transfer-Encoding", "binary")
                w.WriteHeader(200)
            },
            expectedError: fmt.Errorf("unexpected content-transfer-encoding: binary"),
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            testServer := httptest.NewTLSServer(http.HandlerFunc(tc.handlerFunc))
            defer testServer.Close()

            ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))

            client, err := NewBuilder(testServer.URL).
                WithContext(ctx).
                WithClient(http.DefaultClient).
                WithCaCertificates([]*x509.Certificate{testServer.Certificate()}).
                WithDefaultESTAlias(estAlias).
                Build()
            if err != nil {
                t.Fatalf("failed to create client: %s", err.Error())
            }

            _, err = client.CaCerts(estAlias)
            if err == nil {
                t.Fatal("Expected SimpleEnroll to return an error")
            }

            if err.Error() != tc.expectedError.Error() {
                t.Fatalf("Expected error to be %q, got %q", tc.expectedError.Error(), err.Error())
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

func exportCertificateToB64Pkcs7(cert *x509.Certificate) []byte {
	signedData, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		log.Fatalf("Failed to create SignedData: %v", err)
	}

	signedData.AddCertificate(cert)

	signedData.Detach()

	derBytes, err := signedData.Finish()
	if err != nil {
		log.Fatalf("Failed to serialize the SignedData: %v", err)
	}

	base64Str := base64.StdEncoding.EncodeToString(derBytes)

	return []byte(base64Str)
}

func generateCSR(subject string, dnsNames []string, uris []string, ipAddresses []string) ([]byte, *x509.CertificateRequest, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject)
	if err != nil {
		return nil, nil, err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if len(dnsNames) > 0 {
		template.DNSNames = dnsNames
	}

	// Parse and add URIs
	var uriPointers []*url.URL
	for _, u := range uris {
		if u == "" {
			continue
		}
		uriPointer, err := url.Parse(u)
		if err != nil {
			return nil, nil, err
		}
		uriPointers = append(uriPointers, uriPointer)
	}
	template.URIs = uriPointers

	// Parse and add IPAddresses
	var ipAddrs []net.IP
	for _, ipStr := range ipAddresses {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddrs = append(ipAddrs, ip)
	}
	template.IPAddresses = ipAddrs

	// Generate the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, nil, err
	}

	var csrBuf bytes.Buffer
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return nil, nil, err
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, err
	}

	return csrBuf.Bytes(), parsedCSR, nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com"
func parseSubjectDN(subject string) (pkix.Name, error) {
	var name pkix.Name

	if subject == "" {
		return name, nil
	}

	// Split the subject into its individual parts
	parts := strings.Split(subject, ",")

	for _, part := range parts {
		// Split the part into key and value
		keyValue := strings.SplitN(part, "=", 2)

		if len(keyValue) != 2 {
			return pkix.Name{}, asn1.SyntaxError{Msg: "malformed subject DN"}
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		// Map the key to the appropriate field in the pkix.Name struct
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			name.CommonName = value
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}
