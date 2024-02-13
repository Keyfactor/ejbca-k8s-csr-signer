/*
Copyright © 2024 Keyfactor

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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"go.mozilla.org/pkcs7"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Client interface {
	CaCerts(alias string) ([]*x509.Certificate, error)
	SimpleEnroll(alias string, csr string) ([]*x509.Certificate, error)
}

type Builder struct {
	ctx               context.Context
	logger            logr.Logger
	hostname          string
	client            *http.Client
	caCertificates    []*x509.Certificate
	clientCertificate *tls.Certificate
	username          string
	password          string
	defaultESTAlias   string
	errs              []error
}

func NewBuilder(hostname string) *Builder {
	var errs []error

	cleanHostname, err := cleanHostname(hostname)
	if err != nil {
		errs = append(errs, err)
	}

	return &Builder{
		hostname: cleanHostname,
		client:   http.DefaultClient,
        errs:     errs,
	}
}

func (b *Builder) WithClient(client *http.Client) *Builder {
	b.client = client
	return b
}

// WithContext sets the context for the Builder
func (b *Builder) WithContext(ctx context.Context) *Builder {
	b.ctx = ctx
	b.logger = log.FromContext(ctx)
	return b
}

func (b *Builder) WithBasicAuth(username, password string) *Builder {
	b.username = username
	b.password = password
	return b
}

func (c *Builder) WithCaCertificates(caCertificates []*x509.Certificate) *Builder {
	if caCertificates != nil {
		c.caCertificates = caCertificates
	}

	return c
}

func (c *Builder) WithClientCertificate(clientCertificate *tls.Certificate) *Builder {
	c.clientCertificate = clientCertificate

	return c
}

func (b *Builder) WithDefaultESTAlias(alias string) *Builder {
	b.defaultESTAlias = alias
	return b
}

func (b *Builder) Build() (Client, error) {
	if b.hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	tlsConfig := &tls.Config{
		Renegotiation: tls.RenegotiateOnceAsClient,
	}

	if b.clientCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*b.clientCertificate}
	}

	if len(b.caCertificates) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		for _, caCert := range b.caCertificates {
			tlsConfig.RootCAs.AddCert(caCert)
		}

		tlsConfig.ClientCAs = tlsConfig.RootCAs
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = tlsConfig
	customTransport.TLSHandshakeTimeout = 10 * time.Second

	b.client.Transport = customTransport

	return &client{
		logger:          b.logger,
		hostname:        b.hostname,
		client:          b.client,
		basicAuthString: base64.StdEncoding.EncodeToString([]byte(b.username + ":" + b.password)),
		defaultESTAlias: b.defaultESTAlias,
	}, nil
}

type client struct {
	logger          logr.Logger
	hostname        string
	client          *http.Client
	basicAuthString string
	defaultESTAlias string
}

func (e *client) CaCerts(alias string) ([]*x509.Certificate, error) {
	e.logger.Info("Getting CA certificate and chain with EST")

	// Endpoint in the form of /<alias>/cacerts
	endpoint := ""
	if alias != "" {
		endpoint = alias + "/"
	} else if e.defaultESTAlias != "" {
		endpoint = e.defaultESTAlias + "/"
	}
	endpoint += "cacerts"

	url := fmt.Sprintf("https://%s/.well-known/est/%s", e.hostname, endpoint)

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "application/pkcs7-mime")
	request.Header.Set("Accept-Encoding", "base64")

	// No authentication necessary to get the CA certificates

	e.logger.Info(fmt.Sprintf("Prepared a GET request to the CaCerts endpoint: %s", url))

	getCaCertsRestResponse, err := e.client.Do(request)
	if err != nil {
		return nil, err
	}

	if getCaCertsRestResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", getCaCertsRestResponse.StatusCode)
	}

	// Ensure that we got a pkcs7 mime
	content, ok := getCaCertsRestResponse.Header["Content-Type"]
	if !ok || len(content) == 0 || !strings.Contains(content[0], "application/pkcs7-mime") {
		errMsg := "unknown or empty content-type"
		if len(content) > 0 {
			errMsg = fmt.Sprintf("unexpected content-type: %s", content[0])
		}
		return nil, fmt.Errorf(errMsg)
	}

	// Ensure that the response is base64 encoded
	encoding, ok := getCaCertsRestResponse.Header["Content-Transfer-Encoding"]
	if !ok || len(encoding) == 0 || encoding[0] != "base64" {
		errMsg := "unknown or empty content-transfer-encoding"
		if len(encoding) > 0 {
			errMsg = fmt.Sprintf("unexpected content-transfer-encoding: %s", encoding[0])
		}
		return nil, fmt.Errorf(errMsg)
	}

	e.logger.Info("Validated HTTP response headers")

	e.logger.Info("Decoding PKCS#7 mime")

	encodedBytes, err := io.ReadAll(getCaCertsRestResponse.Body)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(encodedBytes))
	if err != nil {
		return nil, err
	}

	parsed, err := pkcs7.Parse(decodedBytes)
	if err != nil {
		return nil, err
	}

	e.logger.Info(fmt.Sprintf("Found %d certificates in chain", len(parsed.Certificates)))

	return parsed.Certificates, nil
}

// SimpleEnroll uses the EJBCA EST endpoint with an optional alias to perform a simple CSR enrollment.
// * alias - optional EJBCA EST alias
// * csr   - Base64 encoded PKCS#10 CSR
func (e *client) SimpleEnroll(alias string, csr string) ([]*x509.Certificate, error) {
	e.logger.Info("Performing a simple CSR enrollment with EST")

	endpoint := ""
	if alias != "" {
		// Use alias passed as argument, if provided
		endpoint = alias + "/"
	} else if e.defaultESTAlias != "" {
		// If not provided, use the default alias, if it exists
		endpoint = e.defaultESTAlias + "/"
	}
	endpoint += "simpleenroll"

	url := fmt.Sprintf("https://%s/.well-known/est/%s", e.hostname, endpoint)

	request, err := http.NewRequest("POST", url, strings.NewReader(csr))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Basic "+e.basicAuthString)
	request.Header.Set("Content-Type", "application/pkcs10")
	request.Header.Set("Content-Transfer-Encoding", "base64")
	request.Header.Set("Accept", "application/pkcs7-mime")
	request.Header.Set("Accept-Encoding", "base64")

	e.logger.Info(fmt.Sprintf("Prepared a POST request to the SimpleEnroll endpoint: %s", url))

	simpleEnrollRestResponse, err := e.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer simpleEnrollRestResponse.Body.Close()

	// Ensure that we got a pkcs7 mime
	content, ok := simpleEnrollRestResponse.Header["Content-Type"]
	if !ok || len(content) == 0 || !strings.Contains(content[0], "application/pkcs7-mime") {
		errMsg := "unknown or empty content-type"
		if len(content) > 0 {
			errMsg = fmt.Sprintf("unexpected content-type: %s", content[0])
		}
		return nil, fmt.Errorf(errMsg)
	}

	// Ensure that the response is base64 encoded
	encoding, ok := simpleEnrollRestResponse.Header["Content-Transfer-Encoding"]
	if !ok || len(encoding) == 0 || encoding[0] != "base64" {
		errMsg := "unknown or empty content-transfer-encoding"
		if len(encoding) > 0 {
			errMsg = fmt.Sprintf("unexpected content-transfer-encoding: %s", encoding[0])
		}
		return nil, fmt.Errorf(errMsg)
	}

	e.logger.Info("Validated HTTP response headers")

	// TODO if Content-Transfer-Encoding is not set, we should assume 7bit

	e.logger.Info("Decoding PKCS#7 mime")

	encodedBytes, err := io.ReadAll(simpleEnrollRestResponse.Body)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(encodedBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS#7 response from EST server: %s", err)
	}

	parsed, err := pkcs7.Parse(decodedBytes)
	if err != nil {
		return nil, err
	}

	e.logger.Info(fmt.Sprintf("Found %d certificates in chain", len(parsed.Certificates)))

	return parsed.Certificates, nil
}

func cleanHostname(hostname string) (string, error) {
	if hostname == "" {
		return "", errors.New("hostname cannot be empty")
	}

	// When parsing a hostname without a scheme, Go will assume it is a path.
	if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
		hostname = "https://" + hostname
	}

	if u, err := url.Parse(hostname); err == nil {
		return u.Host, nil
	} else {
		return "", fmt.Errorf("EJBCA hostname is not a valid URL: %s", err)
	}
}
