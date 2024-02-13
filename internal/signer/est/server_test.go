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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type route struct {
	path    string
	handler func(w http.ResponseWriter, r *http.Request)
}

type Server struct {
	ctx context.Context

	srv     *http.Server
	address string

	tlsCert, tlsKey string

	// routes is a slice of routes that contain path patterns and a corresponding handler.
	routes   []*route
	basePath string

	// patterns is an internal tracking map to quickly determine if there are duplicates in routes.
	patterns map[string]string
}

func NewServer(ctx context.Context) *Server {
	log.Printf("creating new server service")

	server := &Server{
		routes:   make([]*route, 0),
		ctx:      ctx,
		patterns: make(map[string]string),
	}

	return server
}

func (s *Server) WithAddress(address string) *Server {
	log.Printf("using address [%s]", address)

	s.address = address
	return s
}

func (s *Server) WithTLSCertificate(cert, key string) *Server {
	_, certErr := os.Stat(cert)
	_, keyErr := os.Stat(key)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		log.Fatalf("TLS cert [%s] or key [%s] does not exist", cert, key)
	}

	log.Printf("using TLS cert [%s] and key [%s]", cert, key)

	s.tlsCert = cert
	s.tlsKey = key
	return s
}

func (s *Server) WithSelfSignedTLSCertificate() error {
	log.Printf("generating self-signed TLS certificate")

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Set up a certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Boilerplate Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Export the certificate and private key to disk
	certOut, err := os.Create("cert.pem")
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return err
	}
	if err := keyOut.Close(); err != nil {
		return err
	}

	s.tlsCert = "cert.pem"
	s.tlsKey = "key.pem"

	return nil
}

func (s *Server) WithBasePath(basePath string) *Server {
	log.Printf("using base path [%s]", basePath)

	if !strings.HasPrefix(basePath, "/") {
		basePath = fmt.Sprintf("/%s", basePath)
	}

	s.basePath = basePath
	return s
}

func (s *Server) AddRoute(path string, routeHandler func(w http.ResponseWriter, r *http.Request)) *Server {
	if !strings.HasPrefix(path, "/") {
		path = fmt.Sprintf("/%s", path)
	}

	pattern, ok := s.patterns[path]
	if ok {
		log.Printf("duplicate route pattern found [%s]", pattern)

		return s
	}

	log.Printf("adding route [%s]\n", path)

	s.patterns[path] = path
	s.routes = append(s.routes, &route{
		path:    fmt.Sprintf("%s%s", s.basePath, path),
		handler: routeHandler,
	})

	return s
}

func (s *Server) Start() {
	log.Printf("starting server service")
	mux := http.NewServeMux()

	for _, route := range s.routes {
		mux.HandleFunc(route.path, route.handler)
	}

	s.srv = &http.Server{
		Addr:    s.address,
		Handler: mux,
	}

	serveTlsService := s.tlsCert != "" && s.tlsKey != ""

	go func() {
		log.Printf("starting REST server on address [%s]\n", s.address)
		if serveTlsService {
			if err := s.srv.ListenAndServeTLS(s.tlsCert, s.tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		} else {
			if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}
	}()
}

// Shutdown shuts down the http server
func (s *Server) Shutdown() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.srv.Shutdown(s.ctx); err != nil {
			log.Printf("couldn't shutdown server: %s\n", err)
		}
	}()

	select {
	case <-done:
		log.Println("server service shutdown complete")
	case <-s.ctx.Done():
		log.Println("service canceled")
	}
}
