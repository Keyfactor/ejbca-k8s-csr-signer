package controllers

import (
	"context"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/internal/signer"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ signer.Builder = &FakeSignerBuilder{}
var _ signer.Signer = &FakeSignerBuilder{}

type FakeSignerBuilder struct {
	errSign error
}

func (f *FakeSignerBuilder) Reset() signer.Builder {
	return f
}

func (f *FakeSignerBuilder) WithContext(ctx context.Context) signer.Builder {
	return f
}

func (f *FakeSignerBuilder) WithCredsSecret(secret corev1.Secret) signer.Builder {
	return f
}

func (f *FakeSignerBuilder) WithConfigMap(configMap corev1.ConfigMap) signer.Builder {
	return f
}

func (f *FakeSignerBuilder) WithCACertConfigMap(configMap corev1.ConfigMap) signer.Builder {
	return f
}

func (f *FakeSignerBuilder) PreFlight() error {
	return nil
}

func (f *FakeSignerBuilder) Build() signer.Signer {
	return f
}

func (f *FakeSignerBuilder) Sign(csr certificates.CertificateSigningRequest) ([]byte, error) {
	return fakeSuccessCertificate, f.errSign
}

var (
	fakeSuccessCertificate = []byte("fake signed certificate")
	fakeCsr                = []byte("fake csr")
)

const (
	fakeSignerName = "fakesigner.com"
)
