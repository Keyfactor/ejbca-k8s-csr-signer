# Annotation Overrides for the EJBCA K8s CSR Signer

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/ejbca-k8s-csr-signer?label=release)](https://github.com/keyfactor/ejbca-k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/ejbca-k8s-csr-signer.svg)]()

The EJBCA K8s CSR Signer allows you to customize the certificate signing process by using annotations. Annotations can be used to override the default configuration of the signer. The following annotations are supported:

### Supported Annotations
Here are the supported annotations that can override the default values:

- **`ejbca-k8s-csr-signer.keyfactor.com/endEntityName`**: Overrides the `defaultEndEntityName` field from the EJBCA Configuration. Allowed values include `"cn"`, `"dns"`, `"uri"`, `"ip"`, or any custom string.

    ```yaml
    ejbca-k8s-csr-signer.keyfactor.com/endEntityName: "dns"
    ```

- **`ejbca-k8s-csr-signer.keyfactor.com/certificateAuthorityName`**: Specifies the Certificate Authority (CA) name to use, overriding the default CA specified by the `defaultCertificateAuthorityName` field from the EJBCA Configuration.

    ```yaml
    ejbca-k8s-csr-signer.keyfactor.com/certificateAuthorityName: "IT-Sub-CA"
    ```

- **`ejbca-k8s-csr-signer.keyfactor.com/certificateProfileName`**: Specifies the Certificate Profile name to use, overriding the default profile specified by the `defaultCertificateProfileName` field from the EJBCA Configuration.

    ```yaml
    ejbca-k8s-csr-signer.keyfactor.com/certificateProfileName: "istio-3d"
    ```

- **`ejbca-k8s-csr-signer.keyfactor.com/endEntityProfileName`**: Specifies the End Entity Profile name to use, overriding the default profile specified by the `defaultEndEntityProfileName` field from the EJBCA Configuration.

    ```yaml
    ejbca-k8s-csr-signer.keyfactor.com/endEntityProfileName: "k8s-istio"
    ```

- **`ejbca-k8s-csr-signer.keyfactor.com/estAlias`**: Specifies the EST alias to use, overriding the default EST alias specified by the `defaultEstAlias` field from the EJBCA Configuration.

    ```yaml
    ejbca-k8s-csr-signer.keyfactor.com/estAlias: "istio"
    ```

- **`ejbca-k8s-csr-signer.keyfactor.com/chainDepth`**: Specifies the chain depth to use, overriding the default chain depth specified by the `chainDepth` field from the EJBCA Configuration.

    ```yaml
    ejbca-k8s-csr-signer.keyfactor.com/chainDepth: 3
    ```

### How to Apply Annotations

To apply these annotations, include them in the metadata section of your CertificateSigningRequest resource:

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  annotations:
    ejbca-k8s-csr-signer.keyfactor.com/certificateProfileName: istioAuth-3d
    ejbca-k8s-csr-signer.keyfactor.com/endEntityProfileName: k8sEndEntity
    ejbca-k8s-csr-signer.keyfactor.com/certificateAuthorityName: IT-Sub-CA
    # ... other annotations
spec:
# ... rest of the spec
```

### Compatibility with EJBCA CSR Signer v1.0

The annotations recognized in EJBCA K8s CSR Signer v2.0 are backwards compatible with v1.0 until the next major release. The following annotations are recognized in v1.0:
- **`endEntityName`**
- **`certificateAuthorityName`**
- **`certificateProfileName`**
- **`endEntityProfileName`**
- **`estAlias`**