<a href="https://kubernetes.io">
    <img src="https://kubernetes.io/images/favicon.png" alt="Kubernetes logo" title="K8s" align="left" height="50" />
</a>

<a href="https://kubernetes.io">
    <img src="https://helm.sh/img/helm.svg" alt="Helm logo" title="K8s" align="left" height="50" />
</a>

# EJBCA Certificate Signing Request Proxy for K8s 

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/ejbca-k8s-csr-signer?label=release)](https://github.com/keyfactor/ejbca-k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/ejbca-k8s-csr-signer.svg)]()

The EJBCA Certificate Signing Request Proxy for K8s forwards certificate signing requests generated by Kubernetes to [EJBCA](https://www.primekey.com/products/ejbca-enterprise/) for signing by a trusted enterprise certificate authority. The signer operates within the [K8s CertificateSigningRequests API](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/) and implements a Controller that uses the the V1 CertificateSigningRequests informer to handle associated resources. CSRs are only enrolled if they are approved using an [approver](https://github.com/kubernetes/kubernetes/tree/master/pkg/controller/certificates/approver).

## Community supported
We welcome contributions.

The cert-manager external issuer for Keyfactor command is open source and community supported, meaning that there is **no SLA** applicable for these tools.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, see the [contribution guidelines](https://github.com/Keyfactor/command-k8s-csr-signer/blob/main/CONTRIBUTING.md) and use the **[Pull requests](../../pulls)** tab.

## Migration from EJBCA CSR Signer v1.0 to v2.0

The EJBCA CSR Signer v2.0 has breaking changes from v1.0. To migrate from v1.0 to v2.0, uninstall the v1.0 deployment and install the v2.0 deployment. The v2.0 deployment uses the same configuration as v1.0, but the configuration is now stored in a Kubernetes ConfigMap. See the [Getting Started](docs/getting-started.markdown) to install the v2.0 deployment.

## Documentation
* [Getting Started](docs/getting-started.markdown)
* Usage
  * [Demo usage with Istio](docs/istio-deployment.markdown)
  * [Runtime Customization](docs/annotations.markdown)
  * [End Entity Name Selection](docs/endentitynamecustomization.markdown)
* [Testing](docs/testing.markdown)
* [License](LICENSE)
