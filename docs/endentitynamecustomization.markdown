# EJBCA End Entity Name Configuration

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/ejbca-k8s-csr-signer?label=release)](https://github.com/keyfactor/ejbca-k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/ejbca-k8s-csr-signer.svg)]()

The `defaultEndEntityName` field in the Issuer and ClusterIssuer resource spec allows you to configure how the End Entity Name is selected when issuing certificates through EJBCA. This field offers flexibility by allowing you to select different components from the Certificate Signing Request (CSR) or other contextual data as the End Entity Name.

### Configurable Options
Here are the different options you can set for `defaultEndEntityName` in the ConfigMap or `ejbca-k8s-csr-signer.keyfactor.com/endEntityName` as an annotation:

* **`cn`:** Uses the Common Name from the CSR's Distinguished Name.
* **`dns`:** Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **`uri`:** Uses the first URI from the CSR's Subject Alternative Names (SANs).
* **`ip`:** Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
* **Custom Value:** Any other string will be directly used as the End Entity Name.

### Default Behavior
If the endEntityName field is not explicitly set, the EJBCA Issuer will attempt to determine the End Entity Name using the following default behavior:

* **First, it will try to use the Common Name:** It looks at the Common Name from the CSR's Distinguished Name.
* **If the Common Name is not available, it will use the first DNS Name:** It looks at the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **If the DNS Name is not available, it will use the first URI:** It looks at the first URI from the CSR's Subject Alternative Names (SANs).
* **If the URI is not available, it will use the first IP Address:** It looks at the first IP Address from the CSR's Subject Alternative Names (SANs).
* **If none of the above are available:** The certificate issuance will fail.

If the Issuer is unable to determine a valid End Entity Name through these steps, an error will be logged and no End Entity Name will be set.
