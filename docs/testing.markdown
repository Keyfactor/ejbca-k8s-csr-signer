# Testing the EJBCA K8s CSR Signer Source Code

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/ejbca-k8s-csr-signer?label=release)](https://github.com/keyfactor/ejbca-k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/ejbca-k8s-csr-signer.svg)]()

The test cases for the controller require a set of environment variables to be set. These variables are used to
authenticate to an EJBCA API server and to enroll a certificate. The test cases are run using the `make test` command.

The following environment variables must be exported before testing the controller:
- **EJBCA_CA_CERT_PATH**: The path to the CA certificate.
- **EJBCA_CA_NAME**: The name of the Certificate Authority.
- **EJBCA_CERTIFICATE_PROFILE_NAME**: The name of the certificate profile.
- **EJBCA_CLIENT_CERT_PATH**: The path to the client certificate.
- **EJBCA_CSR_SUBJECT**: The subject for the Certificate Signing Request (CSR).
- **EJBCA_END_ENTITY_PROFILE_NAME**: The name of the end entity profile.
- **EJBCA_EST_ALIAS**: Alias for EST.
- **EJBCA_EST_PASSWORD**: Password for EST.
- **EJBCA_EST_USERNAME**: Username for EST.
- **EJBCA_HOSTNAME**: The hostname for EJBCA.

To run the test cases, run:
```shell
make test
```