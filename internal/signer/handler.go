package signer

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
	certificates "k8s.io/api/certificates/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"math/rand"
)

var (
	handlerLog = logger.Register("CertificateSigner-Handler")
)

func (cc *CertificateController) handleRequests(ctx context.Context, csr *certificates.CertificateSigningRequest) error {
	if !IsCertificateRequestApproved(csr) {
		handlerLog.Warnf("Certificate request with name %s is not approved", csr.Name)
		return nil
	}
	handlerLog.Infof("Request Certificate - signerName: %s", csr.Spec.SignerName)

	var usages []string
	for _, usage := range csr.Spec.Usages {
		usages = append(usages, string(usage))
	}

	handlerLog.Infof("Request Certificate - usages: %v", usages)

	asn1CSR, _ := pem.Decode(csr.Spec.Request)
	parsedRequest, err := x509.ParseCertificateRequest(asn1CSR.Bytes)
	if err != nil {
		return err
	}

	handlerLog.Tracef("Request Certificate - Subject DN: %s", parsedRequest.Subject.String())

	var chain []byte
	if cc.ejbcaClient.EST == nil {
		err, chain = restEnrollCSR(cc.ejbcaClient, csr)
		if err != nil {
			return err
		}
	} else {
		err, chain = estEnrollCSR(cc.ejbcaClient.EST, csr)
		if err != nil {
			return err
		}
	}

	csr.Status.Certificate = chain

	status, err := cc.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(ctx, csr, v1.UpdateOptions{})
	if err != nil {
		handlerLog.Errorf("Error updating status for csr with name %s: %s", csr.Name, err.Error())
		return err
	}
	handlerLog.Infof("Successfully enrolled CSR. New status: %s", status.Status)

	return nil
}

func estEnrollCSR(client *ejbca.ESTClient, csr *certificates.CertificateSigningRequest) (error, []byte) {
	handlerLog.Debugln("Enrolling CSR with EST client")
	annotations := csr.GetAnnotations()
	alias := ""
	// Get alias from object annotations, if they exist
	a, ok := annotations["estAlias"]
	if ok {
		alias = a
	}

	// Decode PEM encoded PKCS#10 CSR to DER
	block, _ := pem.Decode(csr.Spec.Request)

	// Enroll CSR with simpleenroll
	leaf, err := client.SimpleEnroll(alias, base64.StdEncoding.EncodeToString(block.Bytes))
	if err != nil {
		return err, nil
	}

	// Grab the CA chain of trust from cacerts
	chain, err := client.CaCerts(alias)
	if err != nil {
		return err, nil
	}

	// Encode each to PEM format and append them
	var leafAndChain []byte
	for _, cert := range leaf {
		leafAndChain = append(leafAndChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	for _, cert := range chain {
		leafAndChain = append(leafAndChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	return nil, leafAndChain
}

func restEnrollCSR(client *ejbca.Client, csr *certificates.CertificateSigningRequest) (error, []byte) {
	handlerLog.Debugln("Enrolling CSR with REST client")
	// Configure PKCS10 enrollment with metadata annotations, if they exist.
	config := &ejbca.PKCS10CSREnrollment{
		IncludeChain:       true,
		CertificateRequest: string(csr.Spec.Request),
	}

	annotations := csr.GetAnnotations()
	certificateProfileName, ok := annotations["certificateProfileName"]
	if ok {
		handlerLog.Tracef("Using the %s certificate profile name", certificateProfileName)
		config.CertificateProfileName = certificateProfileName
	}
	endEntityProfileName, ok := annotations["endEntityProfileName"]
	if ok {
		handlerLog.Tracef("Using the %s end entity profile name", endEntityProfileName)
		config.EndEntityProfileName = endEntityProfileName
	}
	certificateAuthorityName, ok := annotations["certificateAuthorityName"]
	if ok {
		handlerLog.Tracef("Using the %s certificate authority", endEntityProfileName)
		config.CertificateAuthorityName = certificateAuthorityName
	}

	// Extract the common name from CSR
	asn1CSR, _ := pem.Decode(csr.Spec.Request)
	parsedRequest, err := x509.ParseCertificateRequest(asn1CSR.Bytes)
	if err != nil {
		return err, nil
	}
	config.Username = parsedRequest.Subject.CommonName

	// Generate random password as it will likely never be used again
	config.Password = randStringFromCharSet(10)

	var chain []byte
	resp, err := client.EnrollPKCS10(config)
	if err != nil {
		return err, nil
	}

	cert, err := base64.StdEncoding.DecodeString(resp.Certificate)
	if err != nil {
		return err, nil
	}
	chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	for _, certificate := range resp.CertificateChain {
		leaf, err := base64.StdEncoding.DecodeString(certificate)
		if err != nil {
			return err, nil
		}

		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})...)
	}

	return nil, chain
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

// IsCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func IsCertificateRequestApproved(csr *certificates.CertificateSigningRequest) bool {
	approved, denied := getCertApprovalCondition(&csr.Status)
	return approved && !denied
}

func getCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return
}
