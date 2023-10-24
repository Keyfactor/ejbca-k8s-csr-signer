package signer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	ejbcaest "github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/util"
	"github.com/go-logr/logr"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"math/rand"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strconv"
)

// ejbcaSigner implements both Signer and Builder interfaces
var _ Builder = &ejbcaSigner{}
var _ Signer = &ejbcaSigner{}

const annotationPrefix = "ejbca-k8s-csr-signer.keyfactor.com/"

type Builder interface {
	Reset() Builder
	WithContext(ctx context.Context) Builder
	WithCredsSecret(corev1.Secret) Builder
	WithConfigMap(corev1.ConfigMap) Builder
	WithCACertConfigMap(corev1.ConfigMap) Builder
	PreFlight() error
	Build() Signer
}

type Signer interface {
	Sign(csr certificates.CertificateSigningRequest) ([]byte, error)
}

type ejbcaSigner struct {
	ctx    context.Context
	logger logr.Logger
	creds  corev1.Secret

	// Given from config
	hostname                        string
	defaultEndEntityName            string
	defaultCertificateProfileName   string
	defaultEndEntityProfileName     string
	defaultCertificateAuthorityName string
	defaultESTAlias                 string
	chainDepth                      int

	// Computed
	errs              []error
	enrollWithEst     bool
	caChain           []*x509.Certificate
	preflightComplete bool

	estClient  *ejbcaest.Client
	restClient *ejbca.APIClient
}

func NewEjbcaSignerBuilder() Builder {
	return &ejbcaSigner{}
}

func (s *ejbcaSigner) Reset() Builder {
	s.errs = make([]error, 0)
	s.enrollWithEst = false
	return s
}

func (s *ejbcaSigner) WithContext(ctx context.Context) Builder {
	s.ctx = ctx
	s.logger = log.FromContext(ctx)
	return s
}

func (s *ejbcaSigner) WithCredsSecret(secret corev1.Secret) Builder {
	if secret.Type == corev1.SecretTypeTLS {
		// If we have a TLS secret, we will assume that we are not enrolling with EST and will authenticate to
		// the EJBCA API using a client certificate
		s.enrollWithEst = false
		s.logger.Info("Found TLS secret. Using EJBCA REST")

		_, ok := secret.Data["tls.crt"]
		if !ok {
			s.errs = append(s.errs, errors.New("tls.crt not found in secret data"))
		}

		_, ok = secret.Data["tls.key"]
		if !ok {
			s.errs = append(s.errs, errors.New("tls.key not found in secret data"))
		}
	} else if secret.Type == corev1.SecretTypeBasicAuth {
		// If we have a non-TLS secret, we will assume that we are enrolling with EST and will authenticate to
		// the EJBCA API using HTTP Basic Auth
		s.enrollWithEst = true
		s.logger.Info("Found BasicAuth secret. Using EJBCA EST")

		_, ok := secret.Data["username"]
		if !ok {
			s.errs = append(s.errs, errors.New("username not found in secret data"))
		}

		_, ok = secret.Data["password"]
		if !ok {
			s.errs = append(s.errs, errors.New("password not found in secret data"))
		}
	} else {
		s.errs = append(s.errs, errors.New("secret type is not TLS or BasicAuth"))
	}

	s.creds = secret
	return s
}

func (s *ejbcaSigner) WithConfigMap(config corev1.ConfigMap) Builder {
	if host, ok := config.Data["ejbcaHostname"]; ok && host != "" {
		s.hostname = config.Data["ejbcaHostname"]
	} else {
		s.errs = append(s.errs, errors.New("ejbcaHostname not found in config map data"))
	}

	if defaultEndEntityName, ok := config.Data["defaultEndEntityName"]; ok && defaultEndEntityName != "" {
		s.defaultEndEntityName = defaultEndEntityName
	}

	if defaultCertificateProfileName, ok := config.Data["defaultCertificateProfileName"]; ok && defaultCertificateProfileName != "" {
		s.defaultCertificateProfileName = defaultCertificateProfileName
	}

	if defaultEndEntityProfileName, ok := config.Data["defaultEndEntityProfileName"]; ok && defaultEndEntityProfileName != "" {
		s.defaultEndEntityProfileName = defaultEndEntityProfileName
	}

	if defaultCertificateAuthorityName, ok := config.Data["defaultCertificateAuthorityName"]; ok && defaultCertificateAuthorityName != "" {
		s.defaultCertificateAuthorityName = defaultCertificateAuthorityName
	}

	if defaultESTAlias, ok := config.Data["defaultESTAlias"]; ok && defaultESTAlias != "" {
		s.defaultESTAlias = defaultESTAlias
	}

	if chainDepth, ok := config.Data["chainDepth"]; ok && chainDepth != "" {
		var err error
		s.chainDepth, err = strconv.Atoi(chainDepth)
		if err != nil {
			s.errs = append(s.errs, errors.New("chainDepth is not an integer"))
		}
	}

	return s
}

func (s *ejbcaSigner) WithCACertConfigMap(config corev1.ConfigMap) Builder {
	if len(config.Data) == 0 {
		return s
	}

	// There is no requirement that the CA certificate is stored under a specific key in the secret, so we can just
	// iterate over the map and effectively set the caCertBytes to the last value in the map
	var caCertBytes string
	for _, caCertBytes = range config.Data {
	}

	// Try to decode caCertBytes as a PEM formatted block
	caChainBlocks, _ := util.DecodePEMBytes([]byte(caCertBytes))
	if len(caChainBlocks) > 0 {
		var caChain []*x509.Certificate
		for _, block := range caChainBlocks {
			// Parse the PEM block into an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				s.errs = append(s.errs, err)
				return s
			}

			caChain = append(caChain, cert)
		}

		s.caChain = caChain
	}

	s.logger.Info(fmt.Sprintf("Found %d CA certificates in the CA certificate config map", len(s.caChain)))

	return s
}

func (s *ejbcaSigner) PreFlight() error {
	var err error

	// Configure the EJBCA API client
	if s.enrollWithEst {
		s.estClient, err = s.newEstClient()
		if err != nil {
			s.errs = append(s.errs, err)
		}
	} else {
		s.restClient, err = s.newRestClient()
		if err != nil {
			s.errs = append(s.errs, err)
		}
	}

	s.logger.Info("Preflight complete")
	s.preflightComplete = true
	return utilerrors.NewAggregate(s.errs)
}

func (s *ejbcaSigner) newRestClient() (*ejbca.APIClient, error) {
	// Create EJBCA API Client
	ejbcaConfig := ejbca.NewConfiguration()

	if ejbcaConfig.Host == "" {
		ejbcaConfig.Host = s.hostname
	}

	clientCertByte, ok := s.creds.Data["tls.crt"]
	if !ok || len(clientCertByte) == 0 {
		return nil, errors.New("tls.crt not found in secret data")
	}

	// Try to decode client certificate as a PEM formatted block
	clientCertPemBlock, clientKeyPemBlock := util.DecodePEMBytes(clientCertByte)

	// If clientCertPemBlock is empty, try to decode the certificate as a DER formatted block
	if len(clientCertPemBlock) == 0 {
		s.logger.Info("tls.crt does not appear to be PEM formatted. Attempting to decode as DER formatted block.")
		// Try to b64 decode the DER formatted block, but don't error if it fails
		clientCertBytes, err := base64.StdEncoding.DecodeString(string(clientCertByte))
		if err == nil {
			clientCertPemBlock = append(clientCertPemBlock, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
		} else {
			// If b64 decoding fails, assume the certificate is DER formatted
			clientCertPemBlock = append(clientCertPemBlock, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertByte})
		}
	}

	// Determine if ejbcaCert contains a private key
	clientCertContainsKey := false
	if clientKeyPemBlock != nil {
		clientCertContainsKey = true
	}

	if !clientCertContainsKey {
		clientKeyBytes, ok := s.creds.Data["tls.key"]
		if !ok || len(clientKeyBytes) == 0 {
			return nil, errors.New("tls.pem not found in secret data")
		}

		// Try to decode client key as a PEM formatted block
		_, tempKeyPemBlock := util.DecodePEMBytes(clientKeyBytes)
		if tempKeyPemBlock != nil {
			clientKeyPemBlock = tempKeyPemBlock
		} else {
			s.logger.Info("tls.key does not appear to be PEM formatted. Attempting to decode as DER formatted block.")
			// Try to b64 decode the DER formatted block, but don't error if it fails
			tempKeyBytes, err := base64.StdEncoding.DecodeString(string(clientKeyBytes))
			if err == nil {
				clientKeyPemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: tempKeyBytes}
			} else {
				// If b64 decoding fails, assume the private key is DER formatted
				clientKeyPemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyBytes}
			}
		}
	}

	// Create a TLS certificate object
	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(clientCertPemBlock[0]), pem.EncodeToMemory(clientKeyPemBlock))
	if err != nil {
		return nil, err
	}

	// Add the TLS certificate to the EJBCA configuration
	ejbcaConfig.SetClientCertificate(&tlsCert)

	// If the CA certificate is provided, add it to the EJBCA configuration
	ejbcaConfig.SetCaCertificates(s.caChain)

	s.logger.Info("Creating EJBCA REST API client")

	// Create EJBCA API Client
	client, err := ejbca.NewAPIClient(ejbcaConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (s *ejbcaSigner) newEstClient() (*ejbcaest.Client, error) {
	// Get username and password from secret
	username, ok := s.creds.Data["username"]
	if !ok {
		return nil, errors.New("username not found in secret data")
	}

	password, ok := s.creds.Data["password"]
	if !ok {
		return nil, errors.New("password not found in secret data")
	}

	ejbcaConfig := &ejbcaest.Config{
		DefaultESTAlias: s.defaultESTAlias,
	}

	// Copy the root CAs to a file on the filesystem
	if len(s.caChain) > 0 {
		bytes, err := util.CompileCertificatesToPemBytes(s.caChain)
		if err != nil {
			s.logger.Error(err, "Failed to compile CA certificates to PEM bytes")
			return nil, err
		}
		err = os.WriteFile("/tmp/cacerts.pem", bytes, 0644)
		if err != nil {
			return nil, err
		}

		ejbcaConfig.CAFile = "/tmp/cacerts.pem"
	}

	ejbcaFactory, err := ejbcaest.ClientFactory(s.hostname, ejbcaConfig)
	if err != nil {
		s.logger.Error(err, "Failed to create EJBCA EST client factory")
		return nil, err
	}

	s.logger.Info("Creating EJBCA EST client")

	ejbcaClient, err := ejbcaFactory.NewESTClient(string(username), string(password))
	if err != nil {
		s.logger.Error(err, "Failed to create EJBCA EST client")
		return nil, err
	}

	return ejbcaClient, nil
}

func (s *ejbcaSigner) Build() Signer {
	if !s.preflightComplete {
		s.logger.Error(fmt.Errorf("preflight not complete"), "preflight must be completed before building signer")
		return nil
	}

	return s
}

func (s *ejbcaSigner) Sign(csr certificates.CertificateSigningRequest) ([]byte, error) {
	if s.enrollWithEst {
		return s.signWithEst(&csr)
	} else {
		return s.signWithRest(&csr)
	}
}

func (s *ejbcaSigner) getEndEntityName(csr *x509.CertificateRequest) string {
	eeName := ""
	// 1. If the endEntityName option is set, determine the end entity name based on the option
	// 2. If the endEntityName option is not set, determine the end entity name based on the CSR

	// cn: Use the CommonName from the CertificateRequest's DN
	if s.defaultEndEntityName == "cn" || s.defaultEndEntityName == "" {
		if csr.Subject.CommonName != "" {
			eeName = csr.Subject.CommonName
			s.logger.Info(fmt.Sprintf("Using CommonName from the CertificateRequest's DN as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	//* dns: Use the first DNSName from the CertificateRequest's DNSNames SANs
	if s.defaultEndEntityName == "dns" || s.defaultEndEntityName == "" {
		if len(csr.DNSNames) > 0 && csr.DNSNames[0] != "" {
			eeName = csr.DNSNames[0]
			s.logger.Info(fmt.Sprintf("Using the first DNSName from the CertificateRequest's DNSNames SANs as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	//* uri: Use the first URI from the CertificateRequest's URI Sans
	if s.defaultEndEntityName == "uri" || s.defaultEndEntityName == "" {
		if len(csr.URIs) > 0 {
			eeName = csr.URIs[0].String()
			s.logger.Info(fmt.Sprintf("Using the first URI from the CertificateRequest's URI Sans as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	//* ip: Use the first IPAddress from the CertificateRequest's IPAddresses SANs
	if s.defaultEndEntityName == "ip" || s.defaultEndEntityName == "" {
		if len(csr.IPAddresses) > 0 {
			eeName = csr.IPAddresses[0].String()
			s.logger.Info(fmt.Sprintf("Using the first IPAddress from the CertificateRequest's IPAddresses SANs as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	// End of defaults; if the endEntityName option is set to anything but cn, dns, or uri, use the option as the end entity name
	if s.defaultEndEntityName != "" && s.defaultEndEntityName != "cn" && s.defaultEndEntityName != "dns" && s.defaultEndEntityName != "uri" {
		eeName = s.defaultEndEntityName
		s.logger.Info(fmt.Sprintf("Using the defaultEndEntityName as the EJBCA end entity name: %q", eeName))
		return eeName
	}

	// If we get here, we were unable to determine the end entity name
	s.logger.Error(fmt.Errorf("unsuccessfully determined end entity name"), fmt.Sprintf("the endEntityName option is set to %q, but no valid end entity name could be determined from the CertificateRequest", s.defaultEndEntityName))

	return eeName
}

func (s *ejbcaSigner) deprecatedAnnotationGetter(annotations map[string]string, annotation string) string {
	annotationValue, ok := annotations[annotation]
	if ok {
		s.logger.Info(fmt.Sprintf("Annotations specified without the %q prefix is deprecated and will be removed in the future. Using %q as %q", annotationPrefix, annotationValue, annotation))
		return annotationValue
	}

	return ""
}

func (s *ejbcaSigner) signWithRest(csr *certificates.CertificateSigningRequest) ([]byte, error) {
	annotations := csr.GetAnnotations()

	parsedCsr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		return nil, err
	}

	// Log the common metadata of the CSR
	s.logger.Info(fmt.Sprintf("Found CSR wtih DN %q and %d DNS SANs, %d IP SANs, and %d URI SANs", parsedCsr.Subject, len(parsedCsr.DNSNames), len(parsedCsr.IPAddresses), len(parsedCsr.URIs)))

	// Override the default end entity name if the annotation is set
	endEntityName, ok := annotations[annotationPrefix+"endEntityName"]
	if ok {
		s.defaultEndEntityName = endEntityName
	} else if endEntityName = s.deprecatedAnnotationGetter(annotations, "endEntityName"); endEntityName != "" {
		s.defaultEndEntityName = endEntityName
	}

	// Determine the EJBCA end entity name
	ejbcaEeName := s.getEndEntityName(parsedCsr)
	if ejbcaEeName == "" {
		return nil, errors.New("failed to determine the EJBCA end entity name")
	}

	s.logger.Info(fmt.Sprintf("Using or Creating EJBCA End Entity called %q", ejbcaEeName))

	// Configure EJBCA PKCS#10 request
	enroll := ejbca.EnrollCertificateRestRequest{
		CertificateProfileName:   ptr(s.defaultCertificateProfileName),
		EndEntityProfileName:     ptr(s.defaultEndEntityProfileName),
		CertificateAuthorityName: ptr(s.defaultCertificateAuthorityName),
		Username:                 ptr(ejbcaEeName),
		Password:                 ptr(randStringFromCharSet(20)),
		IncludeChain:             ptr(true),
	}

	enroll.SetCertificateRequest(string(csr.Spec.Request))

	certificateProfileName, ok := annotations[annotationPrefix+"certificateProfileName"]
	if ok && certificateProfileName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate profile name from CSR annotations", certificateProfileName))
		enroll.SetCertificateProfileName(certificateProfileName)
	} else if certificateProfileName = s.deprecatedAnnotationGetter(annotations, "certificateProfileName"); certificateProfileName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate profile name from CSR annotations", certificateProfileName))
		enroll.SetCertificateProfileName(certificateProfileName)
	}

	endEntityProfileName, ok := annotations[annotationPrefix+"endEntityProfileName"]
	if ok && endEntityProfileName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q end entity profile name from CSR annotations", endEntityProfileName))
		enroll.SetEndEntityProfileName(endEntityProfileName)
	} else if endEntityProfileName = s.deprecatedAnnotationGetter(annotations, "endEntityProfileName"); endEntityProfileName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q end entity profile name from CSR annotations", endEntityProfileName))
		enroll.SetEndEntityProfileName(endEntityProfileName)
	}

	certificateAuthorityName, ok := annotations[annotationPrefix+"certificateAuthorityName"]
	if ok && certificateAuthorityName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate authority from CSR annotations", certificateAuthorityName))
		enroll.SetCertificateAuthorityName(certificateAuthorityName)
	} else if certificateAuthorityName = s.deprecatedAnnotationGetter(annotations, "certificateAuthorityName"); certificateAuthorityName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate authority from CSR annotations", certificateAuthorityName))
		enroll.SetCertificateAuthorityName(certificateAuthorityName)
	}

	chainDepthStr, ok := annotations[annotationPrefix+"chainDepth"]
	if ok {
		chainDepth, err := strconv.Atoi(chainDepthStr)
		if err == nil {
			s.logger.Info(fmt.Sprintf("Using \"%d\" as chain depth from annotation", chainDepth))
			s.chainDepth = chainDepth
		}
	}

	if enroll.GetCertificateProfileName() == "" {
		return nil, errors.New("certificateProfileName was not found")
	}
	if enroll.GetEndEntityProfileName() == "" {
		return nil, errors.New("endEntityProfileName was not found")
	}
	if enroll.GetCertificateAuthorityName() == "" {
		return nil, errors.New("certificateAuthorityName was not found")
	}

	s.logger.Info(fmt.Sprintf("Enrolling certificate with EJBCA with certificate profile name %q, end entity profile name %q, and certificate authority name %q", enroll.GetCertificateProfileName(), enroll.GetEndEntityProfileName(), enroll.GetCertificateAuthorityName()))

	// Enroll certificate
	certificateObject, _, err := s.restClient.V1CertificateApi.EnrollPkcs10Certificate(context.Background()).EnrollCertificateRestRequest(enroll).Execute()
	if err != nil {
		detail := "error enrolling certificate with EJBCA. verify that the certificate profile name, end entity profile name, and certificate authority name are appropriate for the certificate request."

		var bodyError *ejbca.GenericOpenAPIError
		ok = errors.As(err, &bodyError)
		if ok {
			detail += fmt.Sprintf(" - %s", string(bodyError.Body()))
		}

		s.logger.Error(err, detail)

		return nil, fmt.Errorf(detail)
	}

	leafAndChain, _, err := getCertificatesFromEjbcaObject(*certificateObject)
	if err != nil {
		s.logger.Error(err, fmt.Sprintf("error getting certificate from EJBCA response: %s", err.Error()))
		return nil, err
	}

	// Then, construct the PEM list according to chainDepth

	/*
	   chainDepth = 0 => whole chain
	   chainDepth = 1 => just the leaf
	   chainDepth = 2 => leaf + issuer
	   chainDepth = 3 => leaf + issuer + issuer
	   etc
	*/

	// The two scenarios where we want the whole chain are when chainDepth is 0 or greater than the length of the whole chain
	var pemChain []byte
	if s.chainDepth == 0 || s.chainDepth > len(leafAndChain) {
		s.chainDepth = len(leafAndChain)
	}
	for i := 0; i < s.chainDepth; i++ {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafAndChain[i].Raw})...)
	}

	s.logger.Info(fmt.Sprintf("Successfully enrolled certificate with EJBCA and built leaf and chain to depth %d", s.chainDepth))

	// Return the certificate and chain in PEM format
	return pemChain, nil
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func getCertificatesFromEjbcaObject(ejbcaCert ejbca.CertificateRestResponse) ([]*x509.Certificate, bool, error) {
	var certBytes []byte
	var err error
	certChainFound := false

	if ejbcaCert.GetResponseFormat() == "PEM" {
		// Extract the certificate from the PEM string
		block, _ := pem.Decode([]byte(ejbcaCert.GetCertificate()))
		if block == nil {
			return nil, false, errors.New("failed to parse certificate PEM")
		}
		certBytes = block.Bytes
	} else if ejbcaCert.GetResponseFormat() == "DER" {
		// Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
		// Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
		// will give more insight into the failure.
		bytes := []byte(ejbcaCert.GetCertificate())
		for i := 0; i < 2; i++ {
			var tempBytes []byte
			tempBytes, err = base64.StdEncoding.DecodeString(string(bytes))
			if err == nil {
				bytes = tempBytes
			}
		}
		certBytes = append(certBytes, bytes...)

		// If the certificate chain is present, append it to the certificate bytes
		if len(ejbcaCert.GetCertificateChain()) > 0 {
			var chainCertBytes []byte

			certChainFound = true
			for _, chainCert := range ejbcaCert.GetCertificateChain() {
				// Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
				// Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
				// will give more insight into the failure.
				for i := 0; i < 2; i++ {
					var tempBytes []byte
					tempBytes, err = base64.StdEncoding.DecodeString(chainCert)
					if err == nil {
						chainCertBytes = tempBytes
					}
				}

				certBytes = append(certBytes, chainCertBytes...)
			}
		}
	} else {
		return nil, false, errors.New("ejbca returned unknown certificate format: " + ejbcaCert.GetResponseFormat())
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, false, err
	}

	return certs, certChainFound, nil
}

func (s *ejbcaSigner) signWithEst(csr *certificates.CertificateSigningRequest) ([]byte, error) {
	annotations := csr.GetAnnotations()
	alias := "" // Default is already set in the EST client

	// Get alias from object annotations, if they exist
	a, ok := annotations[annotationPrefix+"estAlias"]
	if ok {
		alias = a
		s.logger.Info("Using \"%s\" as EST alias from annotation", alias)
	} else if a = s.deprecatedAnnotationGetter(annotations, "estAlias"); a != "" {
		alias = a
	} else {
		s.logger.Info("No EST alias found in annotations, using default.")
	}

	a, ok = annotations[annotationPrefix+"chainDepth"]
	if ok {
		chainDepth, err := strconv.Atoi(a)
		if err == nil {
			s.logger.Info(fmt.Sprintf("Using \"%d\" as chain depth from annotation", chainDepth))
			s.chainDepth = chainDepth
		}
	}

	// Decode PEM encoded PKCS#10 CSR to DER
	block, _ := pem.Decode(csr.Spec.Request)

	if s.estClient.EST == nil {
		return nil, errors.New("est client is nil - configuration error likely")
	}

	// Enroll CSR with simpleenroll
	leaf, err := s.estClient.EST.SimpleEnroll(alias, base64.StdEncoding.EncodeToString(block.Bytes))
	if err != nil {
		return nil, err
	}

	// Grab the CA chain of trust from cacerts
	chain, err := s.estClient.EST.CaCerts(alias)
	if err != nil {
		return nil, err
	}

	/*
	   chainDepth = 0 => whole chain
	   chainDepth = 1 => just the leaf
	   chainDepth = 2 => leaf + issuer
	   chainDepth = 3 => leaf + issuer + issuer
	   etc
	*/

	// Build a list of the leaf and the whole chain
	var leafAndChain []*x509.Certificate
	leafAndChain = append(leafAndChain, leaf[0])
	leafAndChain = append(leafAndChain, chain...)

	// The two scenarios where we want the whole chain are when chainDepth is 0 or greater than the length of the whole chain
	// IE if chainDepth == len(leafAndChain), the whole chain will be appended anyway
	var pemChain []byte
	if s.chainDepth == 0 || s.chainDepth > len(leafAndChain) {
		s.chainDepth = len(leafAndChain)
	}
	for i := 0; i < s.chainDepth; i++ {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafAndChain[i].Raw})...)
	}

	s.logger.Info(fmt.Sprintf("Successfully enrolled certificate with EJBCA and built leaf and chain to depth %d", s.chainDepth))

	return pemChain, nil
}

func ptr[T any](v T) *T {
	return &v
}

// From https://github.com/hashicorp/terraform-plugin-sdk/blob/v2.10.0/helper/acctest/random.go#L51
func randStringFromCharSet(strlen int) string {
	charSet := "abcdefghijklmnopqrstuvwxyz012346789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = charSet[rand.Intn(len(charSet))]
	}
	return string(result)
}
