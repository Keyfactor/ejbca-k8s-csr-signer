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
be customized in the `values.yaml`. Of primary importance are configuration items
used by EJBCA.
```yaml
ejbca:
  # Optional default certificate profile name used to enroll CSRs
  defaultCertificateProfileName: Authentication-2048-3y
  # Optional default EJBCA end entity profile name used to enroll certificate
  defaultEndEntityProfileName: AdminInternal
  # Optional default EJBCA CA name that will sign the certificate
  defaultCertificateAuthorityName: ManagementCA
  # Option to use the EJBCA EST interface for certificate enrollment
  useEST: false
  
  # Secret and configmap names
  credsSecretName: ejbca-credentials
  clientCertSecretName: ejbca-client-cert
  caCertConfigmapName: ejbca-ca-cert
  configMapName: ejbca-config
```
This data is compiled into a K8s configmap upon packaging the chart.

## Configuring Credentials
The EJBCA K8s proxy supports two methods of authentication. The first uses a client certificate
to authenticate with the EJBCA REST interface. The second uses HTTP Basic authentication
to authenticate with the EJBCA EST interface. EST is disabled by default, but can be enabled by setting
`useEST` to `true` in the `values.yaml` file.

### Creating K8s CA Certificate ConfigMap
If the server TLS certificate used by EJBCA was signed by an untrusted CA, the CA certificate
must be registered with the TLS transport as a trusted source to allow a TLS handshake.
Obtain this certificate and create a K8s secret as follows:
```shell
kubectl -n ejbca create configmap ejbca-ca-cert --from-file certs/ejbcaCA.pem
```
Helm mounts this certificate as a volume to `/etc/ssl/certs`. The GoLang HTTP library loads certificates from this 
directory as per the [x509 library](https://go.dev/src/crypto/x509/root_unix.go).

| :exclamation:  | If a different configmap name was used, ensure that the `values.yaml` file used by the Helm chart must be updated to reflect this change. |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------|

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
| :memo:        | Note that this will create a secret called `ejbca-client-cert`. If a different secret name is used, the `values.yaml` file used by the Helm chart must be updated to reflect this change. |
|---------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

### Creating K8s Credentials Secret
A [sample credentials](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml) file has been 
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
| :memo:  | Note that this will create a secret called `ejbca-credentials`. If a different secret name is used, the `values.yaml` file used by the Helm chart must be updated to reflect this change. |
|---------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| :exclamation: | The credentials file _must_ be named `credentials.yaml`. |
|---------------|----------------------------------------------------------|

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
