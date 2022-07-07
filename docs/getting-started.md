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
2. Create a new K8s namespace for the CSR proxy.
    ```shell
    kubectl create namespace ejbca
    ```
3. Create a new K8s secret containing required credentials for operating with the CSR proxy. A [sample credentials file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml)
   is provided as a reference. Place this file in a known location.
    ```shell
    kubectl -n ejbca create secret generic ejbca-credentials --from-file ./credentials/credentials.yaml
    ```
   
| :memo:        | This will create a secret called `ejbca-credentials`. If a different secret name is used, the `values.yaml` file used by the Helm chart must be updated to reflect this change. |
|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

4. If the EJBCA Enterprise server certificate was signed by an untrusted CA, the [EJBCA Go Client](https://github.com/Keyfactor/ejbca-go-client)
   will not recognize the required APIs as trusted sources. Create a K8s `configmap`
   containing the server CA certificate with the below command:
    ```shell
    kubectl -n ejbca create configmap ejbca-ca-cert --from-file certs/ejbcaCA.pem
    ```
| :exclamation:  | If a different configmap name was used, ensure that the `values.yaml` file used by the Helm chart must be updated to reflect this change. |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------|

5. If using client certificate authentication (IE not using EST), create a tls K8s secret. K8s requires that
   the certificate and private key are in separate files.
    ```shell
    kubectl -n ejbca create secret tls ejbca-client-cert --cert=certs/client.pem --key=certs/client.key
    ```
| :exclamation: | If a different secret name is used, the `values.yaml` file used by the Helm chart must be updated to reflect this change. |
|---------------|---------------------------------------------------------------------------------------------------------------------------|


### Building from Sources
This is optional. Build and upload a Docker container containing the Go application.
```shell
docker build -t <docker_username>/ejbca-k8s-proxy:1.0.0 .
docker login
docker push <docker_username>/ejbca-k8s-proxy:1.0.0
```
Update `values.yaml` with the updated repository name.

### Deploy
Use Helm to deploy the application.
```shell
helm package charts
helm install -n ejbca ejbca-k8s -f charts/values.yaml ./ejbca-csr-signer-0.1.0.tgz
```

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
    shell kubectl get pods --template '{{range .items}}{{.metadata.name}}{{end}}' -n ejbca
    ```

2. [Here](https://github.com/m8rmclaren/go-csr-gen) is a convenient CSR generator and formatter.

3. `CertificateSigningRequest` objects can be configured with the following annotations to override default values configured by `values.yaml`
    ```yaml
    annotations:
        certificateProfileName: Authentication-2048-3y
        endEntityProfileName: AdminInternal
        certificateAuthorityName: ManagementCA
    ```