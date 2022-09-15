# Getting Started with the EJBCA Certificate Signing Request Proxy for K8s

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

For testing environments, it's recommended that [Docker Desktop](https://docs.docker.com/desktop/) is used, since 
[Kubernetes is easily configured](https://docs.docker.com/desktop/kubernetes/) and requires few extra steps. Docker 
Desktop is also compatible with many operating systems.

## Getting Started
1. Install required software and their dependencies if not already present.
2. Create a new namespace for the CSR proxy.
    ```shell
    kubectl create namespace ejbca
    ```
3. Create a secret containing required credentials for operating with the CSR proxy. A [sample credentials file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml)
   is provided as a reference. By default, EST enrollment is disabled, so EJBCA username and password fields can be left blank in the credentials file. If the private key is encrypted, the key password is required. Place this file in a known location.
    ```shell
    kubectl -n ejbca create secret generic ejbca-credentials --from-file ./credentials/credentials.yaml
    ```

| :memo:  | Note that this will create a secret called `ejbca-credentials`. If a different secret name is used, use `--set ejbca.credsSecretName=<secret name>` to reflect this change.   |
|---------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

4. If the EJBCA Enterprise server certificate was signed by an untrusted CA, the [EJBCA Go Client](https://github.com/Keyfactor/ejbca-go-client)
   will not recognize the required APIs as trusted sources. Create a K8s `configmap`
   containing the server CA certificate with the below command:
    ```shell
    kubectl -n ejbca create configmap ejbca-ca-cert --from-file certs/ejbcaCA.pem
    ```
   Helm will not modify trusted root CA configuration if this value is not set.

| :exclamation:  | If a different configmap name was used, use `--set ejbca.caCertConfigmapName=<configmap name>` to reflect this change. |
|----------------|------------------------------------------------------------------------------------------------------------------------|

5. If using client certificate authentication (IE not using EST), create a tls K8s secret. K8s requires that
   the certificate and private key are in separate files. The client certificate must be a PEM encoded certificate as per 
   [Section 5.1 of RFC7468](https://datatracker.ietf.org/doc/html/rfc7468#section-5.1)
   and the private key be a PEM encoded matching PKCS#8 private key as per [Section 11 of RFC7468](https://datatracker.ietf.org/doc/html/rfc7468#section-11).
    ```shell
    kubectl -n ejbca create secret tls ejbca-client-cert --cert=certs/client.pem --key=certs/client.key
    ```

| :memo: | Note that this will create a secret called `ejbca-client-cert`. If a different secret name is used, use `--set ejbca.clientCertSecretName=<secret name>` to reflect this change. |
|--------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| :memo: | Optionally, the client certificate can be injected using Vault. [See vault guide](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/docs/vault.md). |
|--------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|

### Deploy
Use Helm to deploy the application.
```shell
helm upgrade --install ejbca-csr-signer ejbca-csr-signer \
  --repo https://raw.githubusercontent.com/Keyfactor/ejbca-k8s-csr-signer/gh-pages \
  --namespace ejbca --create-namespace
```
This command deploys `ejbca-csr-signer` on the Kubernetes cluster in the default configuration. To customize the installation,
see [helm install](https://helm.sh/docs/helm/helm_install/) and [EJBCA CSR signer documentation](index.md) for command documentation.

### Verify deployment
Get the POD name by running the following command:
```shell
kubectl -n ejbca get pods
```
The status should say `Running` or `ContainerCreating`.
 
### Create a new CertificateSigningRequest resource with the provided sample
A [sample CSR object file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/sample/sample.yaml) is provided 
for getting started. Create a new CSR resource using the following command. Note that the `request` field
contains a Base64 encoded PKCS#10 PEM encoded certificate.
```shell
kubectl -n ejbca apply -f sample/sample.yaml
kubectl -n ejbca get csr
```
To enroll the CSR, it must be approved.
```shell
kubectl -n ejbca certificate approve ejbcaCsrTest
```
View logs by running the following command:
```shell
kubectl -n ejbca logs <POD name>
```

### Tips
1. Run the following command to isolate the pod name.
    ```shell
    kubectl get pods --template '{{range .items}}{{.metadata.name}}{{end}}' -n ejbca
    ```

2. [Here](https://github.com/m8rmclaren/go-csr-gen) is a convenient CSR generator and formatter.

3. `CertificateSigningRequest` objects can be configured with the following annotations to override default values configured by `values.yaml`
    ```yaml
    annotations:
        certificateProfileName: Authentication-2048-3y
        endEntityProfileName: AdminInternal
        certificateAuthorityName: ManagementCA
    ```