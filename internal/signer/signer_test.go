/*
Copyright 2023 The Keyfactor Command Authors.

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

package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/util"
	logrtesting "github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/url"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"testing"
	"time"
)

func TestNewEjbcaSignerBuilder(t *testing.T) {
	signer := NewEjbcaSignerBuilder()
	if signer == nil {
		t.Error("NewEjbcaSignerBuilder() should not return nil")
	}
}

func TestEjbcaSignerBuilder(t *testing.T) {
	signer := &ejbcaSigner{}

	t.Run("WithContext", func(t *testing.T) {
		ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))
		signer.WithContext(ctx)

		if signer.ctx != ctx {
			t.Error("WithContext() should set the context")
		}

		if !signer.logger.Enabled() {
			t.Error("Expected logger to be enabled")
		}
	})

	t.Run("WithCredsSecret", func(t *testing.T) {
		t.Run("REST", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			secret := corev1.Secret{
				Type: corev1.SecretTypeTLS,
			}

			t.Run("Fail", func(t *testing.T) {
				signer.WithCredsSecret(secret)

				if signer.enrollWithEst {
					t.Error("enrollWithEst should be false")
				}

				if len(signer.errs) == 0 {
					t.Error("Expected errors since secret is empty")
				}
			})

			// Clear errors and config
			signer.Reset()

			t.Run("Success", func(t *testing.T) {
				signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				secret.Data = map[string][]byte{
					"tls.crt": []byte("public key"),
					"tls.key": []byte("private key"),
				}

				if signer.enrollWithEst {
					t.Error("enrollWithEst should be false")
				}

				signer.WithCredsSecret(secret)

				if len(signer.errs) != 0 {
					t.Error("Expected no errors since secret is not empty")
				}
			})
		})

		t.Run("EST", func(t *testing.T) {
			secret := corev1.Secret{
				Type: corev1.SecretTypeBasicAuth,
			}

			t.Run("Fail", func(t *testing.T) {
				signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				signer.WithCredsSecret(secret)

				if !signer.enrollWithEst {
					t.Error("enrollWithEst should be true")
				}

				if len(signer.errs) == 0 {
					t.Error("Expected errors since secret is empty")
				}
			})

			// Clear errors and config
			signer.Reset()

			t.Run("Success", func(t *testing.T) {
				signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				secret.Data = map[string][]byte{
					"username": []byte("username"),
					"password": []byte("password"),
				}

				signer.WithCredsSecret(secret)

				if !signer.enrollWithEst {
					t.Error("enrollWithEst should be true")
				}

				if len(signer.errs) != 0 {
					t.Error("Expected no errors since secret is not empty")
				}
			})
		})
	})

	t.Run("WithConfigMap", func(t *testing.T) {
		config := corev1.ConfigMap{}

		t.Run("Fail", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			signer.WithConfigMap(config)

			if len(signer.errs) == 0 {
				t.Error("Expected errors since config is empty")
			}
		})

		// Clear errors and config
		signer.Reset()

		t.Run("chainDepth_not_digit", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			config.Data = map[string]string{
				"chainDepth": "not a digit",
			}

			signer.WithConfigMap(config)

			if len(signer.errs) == 0 {
				t.Error("Expected errors since chainDepth is not a digit")
			}
		})

		// Clear errors and config
		signer.Reset()

		t.Run("Success", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			config.Data = map[string]string{
				"ejbcaHostname":                   "fake-hostname.ejbca.org",
				"defaultEndEntityName":            "cn",
				"defaultCertificateProfileName":   "FakeCertProfile",
				"defaultEndEntityProfileName":     "FakeEndEntityProfile",
				"defaultCertificateAuthorityName": "FakeCAName",
				"defaultESTAlias":                 "FakeESTAlias",
				"chainDepth":                      "2",
			}

			signer.WithConfigMap(config)

			if len(signer.errs) != 0 {
				t.Error("Expected no errors since config is not empty")
			}

			assert.Equal(t, "fake-hostname.ejbca.org", signer.hostname)
			assert.Equal(t, "cn", signer.defaultEndEntityName)
			assert.Equal(t, "FakeCertProfile", signer.defaultCertificateProfileName)
			assert.Equal(t, "FakeEndEntityProfile", signer.defaultEndEntityProfileName)
			assert.Equal(t, "FakeCAName", signer.defaultCertificateAuthorityName)
			assert.Equal(t, "FakeESTAlias", signer.defaultESTAlias)
			assert.Equal(t, 2, signer.chainDepth)
		})
	})

	t.Run("WithCACertConfigMap", func(t *testing.T) {
		caConfig := corev1.ConfigMap{}

		t.Run("InvalidCert", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			caConfig.Data = map[string]string{
				"caCert.crt": "invalid cert",
			}

			signer.WithCACertConfigMap(caConfig)

			if len(signer.caChain) != 0 {
				t.Error("Expected no CA chain since cert is invalid")
			}
		})

		// Clear errors and config
		signer.Reset()

		t.Run("Success", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			certificate, err := generateSelfSignedCertificate()
			if err != nil {
				t.Fatalf("Failed to generate self-signed certificate: %v", err)
			}
			certBytes, err := util.CompileCertificatesToPemBytes([]*x509.Certificate{certificate})
			if err != nil {
				t.Fatalf("Failed to compile certificate to PEM bytes: %v", err)
			}

			caConfig.Data = map[string]string{
				"caCert.crt": string(certBytes),
			}

			signer.WithCACertConfigMap(caConfig)

			if len(signer.caChain) != 1 {
				t.Error("Expected CA chain to have one certificate")
			}

			if len(signer.errs) != 0 {
				t.Error("Expected no errors since config is not empty")
			}
		})
	})
}

func TestEjbcaSigner(t *testing.T) {
	ejbcaConfig := EjbcaTestConfig{}
	err := ejbcaConfig.Get(t)
	if err != nil {
		t.Fatal(err)
	}

	signerConfig := corev1.ConfigMap{
		Data: map[string]string{
			"ejbcaHostname":                   ejbcaConfig.hostname,
			"defaultEndEntityName":            "",
			"defaultCertificateProfileName":   ejbcaConfig.ejbcaCertificateProfileName,
			"defaultEndEntityProfileName":     ejbcaConfig.ejbcaEndEntityProfileName,
			"defaultCertificateAuthorityName": ejbcaConfig.ejbcaCaName,
			"defaultESTAlias":                 ejbcaConfig.estAlias,
			"chainDepth":                      "0",
		},
	}

	caConfig := corev1.ConfigMap{
		Data: map[string]string{
			"caCert.crt": string(ejbcaConfig.caCertBytes),
		},
	}

	t.Run("REST", func(t *testing.T) {
		restCreds := corev1.Secret{
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": ejbcaConfig.clientCertBytes,
				"tls.key": ejbcaConfig.clientKeyBytes,
			},
		}

		// Build the signer
		builder := &ejbcaSigner{}
		builder.
			WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t))).
			WithCredsSecret(restCreds).
			WithConfigMap(signerConfig).
			WithCACertConfigMap(caConfig)

		err = builder.PreFlight()
		if err != nil {
			t.Fatalf("Failed to preflight signer: %v", err)
		}

		signer := builder.Build()

		// Generate a CSR
		csr, _, err := generateCSR(ejbcaConfig.ejbcaCsrDn, []string{}, []string{}, []string{})
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}
		request := certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Request: csr,
			},
		}

		signedCertBytes, err := signer.Sign(request)
		if err != nil {
			t.Errorf("Failed to sign CSR: %v", err)
		}

		// Verify the signed certificate
		certBlock, _ := util.DecodePEMBytes(signedCertBytes)
		if len(certBlock) == 0 {
			t.Error("Failed to decode signed certificate")
		}

		cert, err := x509.ParseCertificate(certBlock[0].Bytes)
		if err != nil {
			t.Errorf("Failed to parse signed certificate: %v", err)
		}

		if cert.Subject.String() != ejbcaConfig.ejbcaCsrDn {
			t.Error("Signed certificate subject does not match CSR subject")
		}
	})

	t.Run("EST", func(t *testing.T) {
		estCreds := corev1.Secret{
			Type: corev1.SecretTypeBasicAuth,
			Data: map[string][]byte{
				"username": []byte(ejbcaConfig.estUsername),
				"password": []byte(ejbcaConfig.estPassword),
			},
		}

		// Build the signer
		builder := &ejbcaSigner{}
		builder.
			WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t))).
			WithCredsSecret(estCreds).
			WithConfigMap(signerConfig).
			WithCACertConfigMap(caConfig)

		err = builder.PreFlight()
		if err != nil {
			t.Fatalf("Failed to preflight signer: %v", err)
		}

		signer := builder.Build()

		// Generate a CSR
		csr, _, err := generateCSR(ejbcaConfig.ejbcaCsrDn, []string{}, []string{}, []string{})
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}
		request := certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Request: csr,
			},
		}

		signedCertBytes, err := signer.Sign(request)
		if err != nil {
			t.Fatalf("Failed to sign CSR: %v", err)
		}

		// Verify the signed certificate
		certBlock, _ := util.DecodePEMBytes(signedCertBytes)
		if len(certBlock) == 0 {
			t.Fatalf("Failed to decode signed certificate")
		}

		cert, err := x509.ParseCertificate(certBlock[0].Bytes)
		if err != nil {
			t.Fatalf("Failed to parse signed certificate: %v", err)
		}

		if cert.Subject.String() != ejbcaConfig.ejbcaCsrDn {
			t.Error("Signed certificate subject does not match CSR subject")
		}
	})

	// Create supported annotations
	supportedAnnotations := map[string]string{
		"ejbca-k8s-csr-signer.keyfactor.com/certificateAuthorityName": ejbcaConfig.ejbcaCaName,
		"ejbca-k8s-csr-signer.keyfactor.com/certificateProfileName":   ejbcaConfig.ejbcaCertificateProfileName,
		"ejbca-k8s-csr-signer.keyfactor.com/endEntityName":            "",
		"ejbca-k8s-csr-signer.keyfactor.com/endEntityProfileName":     ejbcaConfig.ejbcaEndEntityProfileName,
		"ejbca-k8s-csr-signer.keyfactor.com/estAlias":                 ejbcaConfig.estAlias,
		"ejbca-k8s-csr-signer.keyfactor.com/chainDepth":               "5",
	}

	// Create deprecated annotations
	deprecatedAnnotations := map[string]string{
		"certificateAuthorityName": ejbcaConfig.ejbcaCaName,
		"certificateProfileName":   ejbcaConfig.ejbcaCertificateProfileName,
		"endEntityName":            "",
		"endEntityProfileName":     ejbcaConfig.ejbcaEndEntityProfileName,
		"estAlias":                 ejbcaConfig.estAlias,
		"chainDepth":               "5",
	}

	t.Run("RESTWithAnnotations", func(t *testing.T) {
		testRestWithAnnotations := func(t *testing.T, annotations map[string]string) {
			restCreds := corev1.Secret{
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": ejbcaConfig.clientCertBytes,
					"tls.key": ejbcaConfig.clientKeyBytes,
				},
			}

			// Clear out existing config for annotation override
			signerConfig = corev1.ConfigMap{
				Data: map[string]string{
					"ejbcaHostname": ejbcaConfig.hostname,
				},
			}

			// Build the signer
			builder := &ejbcaSigner{}
			builder.
				WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t))).
				WithCredsSecret(restCreds).
				WithConfigMap(signerConfig).
				WithCACertConfigMap(caConfig)

			err = builder.PreFlight()
			if err != nil {
				t.Fatalf("Failed to preflight signer: %v", err)
			}

			signer := builder.Build()

			// Generate a CSR
			csr, _, err := generateCSR(ejbcaConfig.ejbcaCsrDn, []string{}, []string{}, []string{})
			if err != nil {
				t.Fatalf("Failed to generate CSR: %v", err)
			}
			request := certificates.CertificateSigningRequest{
				Spec: certificates.CertificateSigningRequestSpec{
					Request: csr,
				},
			}

			request.SetAnnotations(annotations)

			signedCertBytes, err := signer.Sign(request)
			if err != nil {
				t.Fatalf("Failed to sign CSR: %v", err)
			}

			// Verify the signed certificate
			certBlock, _ := util.DecodePEMBytes(signedCertBytes)
			if len(certBlock) == 0 {
				t.Error("Failed to decode signed certificate")
			}

			cert, err := x509.ParseCertificate(certBlock[0].Bytes)
			if err != nil {
				t.Errorf("Failed to parse signed certificate: %v", err)
			}

			if cert.Subject.String() != ejbcaConfig.ejbcaCsrDn {
				t.Error("Signed certificate subject does not match CSR subject")
			}
		}

		t.Run("Supported", func(t *testing.T) {
			testRestWithAnnotations(t, supportedAnnotations)
		})

		t.Run("Deprecated", func(t *testing.T) {
			testRestWithAnnotations(t, deprecatedAnnotations)
		})
	})

	t.Run("ESTWithAnnotations", func(t *testing.T) {
		testEstWithAnnotations := func(t *testing.T, annotations map[string]string) {
			estCreds := corev1.Secret{
				Type: corev1.SecretTypeBasicAuth,
				Data: map[string][]byte{
					"username": []byte(ejbcaConfig.estUsername),
					"password": []byte(ejbcaConfig.estPassword),
				},
			}

			// Clear out existing config for annotation override
			signerConfig = corev1.ConfigMap{
				Data: map[string]string{
					"ejbcaHostname": ejbcaConfig.hostname,
				},
			}

			// Build the signer
			builder := &ejbcaSigner{}
			builder.
				WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t))).
				WithCredsSecret(estCreds).
				WithConfigMap(signerConfig).
				WithCACertConfigMap(caConfig)

			err = builder.PreFlight()
			if err != nil {
				t.Fatalf("Failed to preflight signer: %v", err)
			}

			signer := builder.Build()

			// Generate a CSR
			csr, _, err := generateCSR(ejbcaConfig.ejbcaCsrDn, []string{}, []string{}, []string{})
			if err != nil {
				t.Fatalf("Failed to generate CSR: %v", err)
			}
			request := certificates.CertificateSigningRequest{
				Spec: certificates.CertificateSigningRequestSpec{
					Request: csr,
				},
			}

			request.SetAnnotations(annotations)

			signedCertBytes, err := signer.Sign(request)
			if err != nil {
				t.Fatalf("Failed to sign CSR: %v", err)
			}

			// Verify the signed certificate
			certBlock, _ := util.DecodePEMBytes(signedCertBytes)
			if len(certBlock) == 0 {
				t.Fatalf("Failed to decode signed certificate")
			}

			cert, err := x509.ParseCertificate(certBlock[0].Bytes)
			if err != nil {
				t.Fatalf("Failed to parse signed certificate: %v", err)
			}

			if cert.Subject.String() != ejbcaConfig.ejbcaCsrDn {
				t.Error("Signed certificate subject does not match CSR subject")
			}
		}

		t.Run("Supported", func(t *testing.T) {
			testEstWithAnnotations(t, supportedAnnotations)
		})

		t.Run("Deprecated", func(t *testing.T) {
			testEstWithAnnotations(t, deprecatedAnnotations)
		})
	})

	// Test the default end entity name conditionals
	t.Run("DefaultEndEntityNameTests", func(t *testing.T) {
		builder := &ejbcaSigner{}

		// Test when endEntityName is not set
		t.Run("endEntityName is not set", func(t *testing.T) {
			builder.defaultEndEntityName = ""

			t.Run("CN", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, "purplecat.example.com", builder.getEndEntityName(csr))
			})

			t.Run("DNS", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				// Generate a CSR
				_, csr, err := generateCSR("", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "reddog.example.com")
			})

			t.Run("URI", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				// Generate a CSR
				_, csr, err := generateCSR("", []string{""}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, "https://blueelephant.example.com", builder.getEndEntityName(csr))
			})

			t.Run("IP", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				// Generate a CSR
				_, csr, err := generateCSR("", []string{""}, []string{""}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "192.168.1.1")
			})
		})

		// Test when endEntityName is set
		t.Run("endEntityName is set", func(t *testing.T) {
			t.Run("CN", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				builder.defaultEndEntityName = "cn"

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "purplecat.example.com")
			})

			t.Run("DNS", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				builder.defaultEndEntityName = "dns"

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "reddog.example.com")
			})

			t.Run("URI", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				builder.defaultEndEntityName = "uri"

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "https://blueelephant.example.com")
			})

			t.Run("IP", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				builder.defaultEndEntityName = "ip"

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "192.168.1.1")
			})

			t.Run("endEntityName", func(t *testing.T) {
				builder.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

				builder.defaultEndEntityName = "Hello World!"

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, builder.getEndEntityName(csr), "Hello World!")
			})
		})
	})
}

type EjbcaTestConfig struct {
	hostname                    string
	ejbcaCaName                 string
	ejbcaCertificateProfileName string
	ejbcaEndEntityProfileName   string
	ejbcaCsrDn                  string
	estAlias                    string

	clientCertBytes []byte
	clientKeyBytes  []byte
	caCertBytes     []byte

	estUsername string
	estPassword string
}

func (c *EjbcaTestConfig) Get(t *testing.T) error {
	var errs []error

	// Paths
	pathToClientCert := os.Getenv("EJBCA_CLIENT_CERT_PATH")
	pathToCaCert := os.Getenv("EJBCA_CA_CERT_PATH")

	// EJBCA Config
	c.hostname = os.Getenv("EJBCA_HOSTNAME")
	c.ejbcaCaName = os.Getenv("EJBCA_CA_NAME")
	c.ejbcaCertificateProfileName = os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME")
	c.ejbcaEndEntityProfileName = os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME")
	c.ejbcaCsrDn = os.Getenv("EJBCA_CSR_SUBJECT")
	c.estAlias = os.Getenv("EJBCA_EST_ALIAS")
	c.estUsername = os.Getenv("EJBCA_EST_USERNAME")
	c.estPassword = os.Getenv("EJBCA_EST_PASSWORD")

	if pathToClientCert == "" {
		err := errors.New("EJBCA_CLIENT_CERT_PATH environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if pathToCaCert == "" {
		err := errors.New("EJBCA_CA_CERT_PATH environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.hostname == "" {
		err := errors.New("EJBCA_HOSTNAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.ejbcaCaName == "" {
		err := errors.New("EJBCA_CA_NAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.ejbcaCertificateProfileName == "" {
		err := errors.New("EJBCA_CERTIFICATE_PROFILE_NAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.ejbcaEndEntityProfileName == "" {
		err := errors.New("EJBCA_END_ENTITY_PROFILE_NAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.ejbcaCsrDn == "" {
		err := errors.New("EJBCA_CSR_SUBJECT environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.estAlias == "" {
		err := errors.New("EJBCA_EST_ALIAS environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.estUsername == "" {
		err := errors.New("EJBCA_EST_USERNAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.estPassword == "" {
		err := errors.New("EJBCA_EST_PASSWORD environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	// Read the client cert and key from the file system.
	clientCertBytes, err := os.ReadFile(pathToClientCert)
	if err != nil {
		t.Errorf("Failed to read client cert from file system: %v", err)
		errs = append(errs, err)
	}
	clientCerts, priv := util.DecodePEMBytes(clientCertBytes)
	if len(clientCerts) == 0 {
		err = errors.New("failed to decode client cert")
		t.Error(err)
		errs = append(errs, err)
	} else {
		c.clientCertBytes = pem.EncodeToMemory(clientCerts[0])
	}
	if priv == nil {
		err = errors.New("failed to decode client key")
		t.Error(err)
		errs = append(errs, err)
	} else {
		c.clientKeyBytes = pem.EncodeToMemory(priv)
	}

	// Read the CA cert from the file system.
	caCertBytes, err := os.ReadFile(pathToCaCert)
	if err != nil {
		t.Errorf("Failed to read CA cert from file system: %v", err)
		errs = append(errs, err)
	}
	c.caCertBytes = caCertBytes

	return utilerrors.NewAggregate(errs)
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

func generateCSR(subject string, dnsNames []string, uris []string, ipAddresses []string) ([]byte, *x509.CertificateRequest, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
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
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
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
			if randomizeCn {
				name.CommonName = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}

func generateRandomString(length int) string {
	mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	return string(b)
}
