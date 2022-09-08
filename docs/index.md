# Documentation for the EJBCA Certificate Signing Request Proxy for K8s

## Requirements
* EJBCA
    * [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)
* Docker (to build the container)
    * [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* Kubernetes (v1.19 +)
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/) or [Minikube](https://minikube.sigs.k8s.io/docs/start/)
    * Or [Kubernetes with Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
* Helm (to deploy Kubernetes)
    * [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

## Configuring the proxy
The EJBCA K8s proxy is deployed using a Helm chart. As such, various configuration items can
be customized using values. Values are configured by using the `--set` flag during chart installation.
See [helm install](https://helm.sh/docs/helm/helm_install/) for command documentation.

| Key                                        | Type   | Default                        | Description                                                                                                                                                                                                                                                                                                |
|--------------------------------------------|--------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ejbca.image.repository                     | string | `m8rmclarenkf/ejbca-k8s-proxy` | Repository containing EJBCA K8s CSR proxy container image                                                                                                                                                                                                                                                  |
| ejbca.image.pullPolicy                     | string | `IfNotPresent`                 | Image pull policy                                                                                                                                                                                                                                                                                          |
| ejbca.image.tag                            | string | `0.2.92`                       | CSR signer tag                                                                                                                                                                                                                                                                                             |
| ejbca.useEST                               | bool   | `false`                        | Boolean that configures proxy to use the EST protocol for CSR enrollment. If set to true, credentials must be provided in the credentials secret. [sample credentials file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml)                                           |
| ejbca.healthcheckPort                      | int    | 5354                           | Healthcheck port used by K8s to get the health of application                                                                                                                                                                                                                                              |
| ejbca.defaultESTAlias                      | string | `""`                           | Default EST alias used for CSR enrollment if `ejbca.useEST` is set to true and estAlias is not configured as an annotation on K8s CSR object.                                                                                                                                                              |
| ejbca.defaultCertificateProfileName        | string | `""`                           | Default certificate profile name used for CSR enrollment if `ejbca.useEST` is set to false and certificateProfileName is not configured as an annotation on K8s CSR object.                                                                                                                                |
| ejbca.defaultEndEntityProfileName          | string | `""`                           | Default end entity profile name used for CSR enrollment if `ejbca.useEST` is set to false and endEntityProfileName is not configured as an annotation on K8s CSR object.                                                                                                                                   |
| ejbca.defaultCertificateAuthorityName      | string | `""`                           | Default certificate authority name used for CSR enrollment if `ejbca.useEST` is set to false and certificateAuthorityName is not configured as an annotation on K8s CSR object.                                                                                                                            |
| ejbca.credsSecretName                      | string | `ejbca-credentials`            | Credentials secret name that contains `credentials.yaml` as provided in [sample credentials file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml)                                                                                                                     |
| ejbca.clientCertSecretName                 | string | `ejbca-client-cert`            | Secret containing client certificate key pair used for authentication to EJBCA if `ejbca.useEST` is false. It's recommended that `ejbca.vault` is configured to get this credential from HashiCorp Vault, as K8s secret objects have security limitations.                                                 |
| ejbca.caCertConfigmapName                  | string | `""`                           | Name of K8s ConfigMap containing PEM encoded root CA certificate if the EJBCA host certificate was signed by an untrusted host.                                                                                                                                                                            |
| ejbca.chainDepth                           | int    | `0`                            | Integer that configures the certificate chain depth included with the update CSR object. 0 => full chain; 1 => leaf only; 2 => issuer; 3 => issuer's issuer; etc.                                                                                                                                          |
| ejbca.signernames                          | list   | `{keyfactor.com*/}`            | List of signer names that the CSR signer is authorized to sign certificates for.                                                                                                                                                                                                                           |
| ejbca.vault.enabled                        | bool   | `false`                        | Boolean that configures chart to enable Vault sidecar injector to inject client certificate stored in HashiCorp Vault. Only valid if `ejbca.useEST` is false.                                                                                                                                              |
| ejbca.vault.roleName                       | string | `"ejbca-cred"`                 | String indicating the name of the role and policy in Vault granting access to the secret containing client certificate. Note that if `serviceAccount.create=false`, a service account must be created with the same name as `ejbca.vault.roleName`, and `serviceAccount.name` must be updated accordingly. |
| ejbca.vault.vaultSecretPath                | string | `secret/data/ejbca`            | String containing the path to the vault secret.                                                                                                                                                                                                                                                            |
| serviceAccount.create                      | bool   | `true`                         | Boolean that configures helm to create service account. If this is false, `serviceAccount.name` must be updated to configure a service account for the deployment object.                                                                                                                                  |
| serviceAccount.annotations                 | list   | `{}`                           | List of annotations to attach to serviceAccount definition                                                                                                                                                                                                                                                 |
| serviceAccount.name                        | string | `"ejbca-k8s"`                  | Service account name used if `ejbca.vault.enabled=false`                                                                                                                                                                                                                                                   |
| podSecurityContext                         | object | `{}`                           |                                                                                                                                                                                                                                                                                                            |
| securityContext                            | object | `{}`                           |                                                                                                                                                                                                                                                                                                            |
| resources                                  | object | `{}`                           |                                                                                                                                                                                                                                                                                                            |
| autoscaling.enabled                        | bool   | `true`                         |                                                                                                                                                                                                                                                                                                            |
| autoscaling.minReplicas                    | int    | `1`                            |                                                                                                                                                                                                                                                                                                            |
| autoscaling.maxReplicas                    | int    | `100`                          |                                                                                                                                                                                                                                                                                                            |
| autoscaling.targetCPUUtilizationPercentage | int    | `80`                           |                                                                                                                                                                                                                                                                                                            |
| nodeSelector                               | object | `{}`                           |                                                                                                                                                                                                                                                                                                            |
| tolerations                                | list   | `{}`                           |                                                                                                                                                                                                                                                                                                            |
| affinity                                   | object | `{}`                           |                                                                                                                                                                                                                                                                                                            |

### Custom signer names
When `CertificateSigningRequest` objects are created, the `spec.signerName` field tells K8s which signer should sign the CSR after it gets approved.
By default, `ejbca-k8s-signer` is configured to sign CSRs with signerName `"keyfactor.com/*"`. This can be customized by setting the `ejbca.signerNames` value. This feature allows for multiple signers with different behavior to exist in the same cluster.
For example, an application could require certificates enrolled by a specific CA and a custom certificate/end entity profile. The following installation can be used to
fulfill this requirement.
```shell
helm upgrade --install ejbca-csr-signer ejbca-csr-signer \
  --repo https://github.com/Keyfactor/ejbca-k8s-csr-signer \
  --namespace ejbca \
  --set "ejbca.useEST=false" \
  --set "ejbca.clientCertSecretName=ejbca-client-cert" \
  --set "ejbca.signerNames={example.com/feature}" \
  --set "ejbca.defaultCertificateProfileName=featureCertificateProfileName" \
  --set "ejbca.defaultEndEntityProfileName=featureEEProfile" \
  --set "ejbca.defaultCertificateAuthorityName=Feature-Sub-CA"
```
Now, the application can be configured to use `example.com/feature` as its `spec.signerName`, and certificates will be enrolled
off the `Feature-Sub-CA` certificate authority using the `featureCertificateProfileName` certificate profile and `featureEEProfile` end entity profile.
Note that these fields can also be customized using annotations, detailed in the [Using the CSR Proxy](#Using the CSR Proxy) section.

## Configuring Credentials
The EJBCA K8s proxy supports two methods of authentication. The first uses a client certificate
to authenticate with the EJBCA REST interface. The second uses HTTP Basic authentication
to authenticate with the EJBCA EST interface. EST is disabled by default, but can be enabled using
`--set ejbca.useEST=true`.

### Untrusted root CA certificate
If the server TLS certificate used by EJBCA was signed by an untrusted CA, the CA certificate
must be registered with the TLS transport as a trusted source to allow a TLS handshake.
Obtain this certificate and create a K8s secret as follows:
```shell
kubectl -n ejbca create configmap ejbca-ca-cert --from-file certs/ejbcaCA.pem
```
Then, use `-- set ejbca.caCertConfigmapName=ejbca-ca-cert`. This value is blank by default.
Helm mounts this certificate as a volume to `/etc/ssl/certs`. The GoLang HTTP library loads certificates from this 
directory as per the [x509 library](https://go.dev/src/crypto/x509/root_unix.go).

| :exclamation:  | If a different configmap name was used, use `--set ejbca.caCertConfigmapName=<configmap name>` to reflect this change. |
|----------------|------------------------------------------------------------------------------------------------------------------------|

### Creating K8s Client Certificate Secret
If the traditional REST client is used (IE EST is not being used), a K8s TLS secret must
be created containing the client certificate/keypair. K8s requires that this certificate
be a PEM or DER encoded certificate as per [Section 5.1 of RFC7468](https://datatracker.ietf.org/doc/html/rfc7468#section-5.1)
and the private key be a PEM or DER encoded matching private key as per [Section 11 of RFC7468](https://datatracker.ietf.org/doc/html/rfc7468#section-11).
Once located, create the secret with the following command:
```shell
kubectl create secret tls ejbca-client-cert \
  --cert=path/to/cert/file \
  --key=path/to/key/file
```

| :memo:        | Note that this will create a secret called `ejbca-client-cert`. If a different secret name is used, use `--set ejbca.clientCertSecretName=<secret name>` to reflect this change. |
|---------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| :memo: | For non-testing environments, it's recommended that the client certificate come from a more secure source. [See vault guide for more](vault.md). |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------|

### Creating K8s Credentials Secret
A [sample credentials](../credentials/sample.yaml) file has been 
provided for easier configuration of the K8s proxy. Populate this file with appropriate configuration.
```yaml
# Hostname to EJBCA server
hostname: ""

# Password used to protect private key, if it's encrypted according to RFC 1423. Leave blank if private key
# is not encrypted.
keyPassword: ""

# EJBCA username used if the proxy was configured to use EST for enrollment. To enable EST, set useEST to true in values.yaml.
ejbcaUsername: ""

# EJBCA password used if the proxy was configured to use EST for enrollment.
ejbcaPassword: ""
```
Once the file has been populated, run the following command to create a K8s secret.
```shell
kubectl create secret generic ejbca-credentials --from-file ./credentials/credentials.yaml
```

| :memo:  | Note that this will create a secret called `ejbca-credentials`. If a different secret name is used, use `--set ejbca.credsSecretName=<secret name>` to reflect this change.   |
|---------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

### Building from Sources
This is optional. Build and upload a Docker container containing the Go application.
```shell
docker build -t <docker_username>/ejbca-k8s-proxy:1.0.0 .
docker login
docker push <docker_username>/ejbca-k8s-proxy:1.0.0
```
Update `values.yaml` with the updated repository name and version.

## Using the CSR Proxy
The EJBCA K8s CSR Proxy interfaces with the Kubernetes `certificates.k8s.io/v1` API.
To create a CSR, create a `CertificateSigningRequest` object. A template is shown below:
```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  # Name of CSR that K8s will use to track approval and manage the CSR object
  name: ejbcaCsrTest
  annotations:
	# Optional EJBCA certificate profile name to enroll the certificate with
    certificateProfileName: a
    # Optional EJBCA end entity profile name used to enroll certificate
    endEntityProfileName: b
    # Optional EJBCA CA name that will sign the certificate
    certificateAuthorityName: c
    # Optional EST alias if ejbca.useEST=true
    estAlias: d
spec:
  # Base64 encoded PKCS#10 CSR
  request: ==
  usages:
    - client auth
    - server auth
  signerName: "keyfactor.com/kubernetes-integration"
```
| :exclamation: | The annotations shown in the example CSR object configuration are not optional if defaults were not configured in `values.yaml` |
|---------------|---------------------------------------------------------------------------------------------------------------------------------|

| :memo: | [Here](https://github.com/m8rmclaren/go-csr-gen) is a convenient CSR generator and formatter. |
|--------|-----------------------------------------------------------------------------------------------|
