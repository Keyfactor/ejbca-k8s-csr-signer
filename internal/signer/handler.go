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
		err, chain = restEnrollCSR(cc.ejbcaClient, csr, cc.chainDepth)
		if err != nil {
			return err
		}
	} else {
		err, chain = estEnrollCSR(cc.ejbcaClient.EST, csr, cc.chainDepth)
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

func estEnrollCSR(client *ejbca.ESTClient, csr *certificates.CertificateSigningRequest, chainDepth int) (error, []byte) {
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

	// Build a list of the leaf and the whole chain
	var leafAndChain []*x509.Certificate
	leafAndChain = append(leafAndChain, leaf[0])
	for _, cert := range chain {
		leafAndChain = append(leafAndChain, cert)
	}

	// The two scenarios where we want the whole chain are when chainDepth is 0 or greater than the length of the whole chain
	// IE if chainDepth == len(leafAndChain), the whole chain will be appended anyway
	var pemChain []byte
	if chainDepth == 0 || chainDepth > len(leafAndChain) {
		chainDepth = len(leafAndChain)
	}
	for i := 0; i < chainDepth; i++ {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafAndChain[i].Raw})...)
	}

	return nil, pemChain
}

func restEnrollCSR(client *ejbca.Client, csr *certificates.CertificateSigningRequest, chainDepth int) (error, []byte) {
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
	if parsedRequest.Subject.CommonName != "" {
		config.Username = parsedRequest.Subject.CommonName
	} else {
		config.Username = randStringFromCharSet(10)
	}

	// Generate random password as it will likely never be used again
	config.Password = randStringFromCharSet(10)

	var leafAndChain []*x509.Certificate
	resp, err := client.EnrollPKCS10(config)
	if err != nil {
		return err, nil
	}

	// Build a list of the leaf and the whole chain
	leafAndChain = append(leafAndChain, resp.Certificate)
	for _, cert := range resp.CertificateChain {
		leafAndChain = append(leafAndChain, cert)
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
	if chainDepth == 0 || chainDepth > len(leafAndChain) {
		chainDepth = len(leafAndChain)
	}
	for i := 0; i < chainDepth; i++ {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafAndChain[i].Raw})...)
	}

	return nil, pemChain
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
