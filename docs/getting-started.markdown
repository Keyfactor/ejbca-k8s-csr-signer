# Getting Started with the EJBCA Certificate Signing Request Proxy for K8s

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/ejbca-k8s-csr-signer?label=release)](https://github.com/keyfactor/ejbca-k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/ejbca-k8s-csr-signer.svg)]()

## Requirements
* EJBCA
    * [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)
* Docker (to build the container)
    * [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) (v1.11.3 +)
* Kubernetes (v1.19 +)
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/)
    * [Minikube](https://minikube.sigs.k8s.io/docs/start/)
    * [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
    * [Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
    * [Azure Kubernetes](https://azure.microsoft.com/en-us/products/kubernetes-service)
    * [Amazon EKS](https://aws.amazon.com/eks/)
    * [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine)
* Helm (to deploy to Kubernetes)
    * [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

## Getting Started
Install required software and their dependencies if not already present. Additionally, verify that at least one Kubernetes node is running by running the following command:

```shell
kubectl get nodes
```

### 1. Building the Container Image

The EJBCA K8s CSR Signer is distributed as source code, and the container must be built manually. The container image can be built using the following command:
```shell
make docker-build DOCKER_REGISTRY=<your container registry> DOCKER_IMAGE_NAME=keyfactor/ejbca-k8s-csr-signer
```

###### :pushpin: The container image can be built using Docker Buildx by running `make docker-buildx`. This will build the image for all supported platforms.

### 2. Prepare Credentials and Configuration

1. Create a new namespace for the CSR proxy.
    ```shell
    kubectl create namespace ejbca-signer-system
    ```

2. The EJCBA K8s CSR Signer can enroll certificates using the EJBCA REST API and with EST.

    * If you want to configure the signer to enroll certificates using the EJBCA REST API (IE EST is not configured), authentication to the EJBCA API is handled using client certificates.

        Create a `kubernetes.io/tls` secret containing the client certificate and key. The secret must be created in the same namespace as the CSR proxy.
        
        ```shell
        kubectl create secret tls ejbca-credentials \
            --namespace ejbca-signer-system \
            --cert=<path to client certificate> \
            --key=<path to client key>
        ```

    * If you want to configure the signer to enroll certificates using EST, authentication to the EJBCA API is handled using HTTP Basic Authentication.

        Create a `kubernetes.io/basic-auth` secret containing the username and password. The secret must be created in the same namespace as the CSR proxy.
        
        ```shell
        kubectl -n ejbca create secret generic ejbca-credentials \
            --namespace ejbca-signer-system \
            --type=kubernetes.io/basic-auth \
            --from-literal=username=<username> \
            --from-literal=password=<password>
        ```

3. The EJCBA K8s CSR Signer uses a K8s ConfigMap to configure how certificates are signed by EJBCA, and how signed certificates are stored back into Kubernetes. A [sample](../ejbca-signer-config.yaml) ConfigMap is provided as a reference.

    The following fields are required:
    * `ejbcaHostname`: The hostname of the EJBCA instance.
    * `chainDepth`: The length of the certificate chain included with the leaf certificate. For example, a value of `0` will include the whole chain up to the root CA, and a value of `2` will include the leaf certificate and one intermediate CA certificate.

    * If you want to configure the signer to enroll certificates using the EJBCA REST API, the following fields must be configured:
        * `defaultEndEntityName`: The name of the end entity to use. More information on how the field is used can be found in the [EJBCA End Entity Name Configuration](endentitynamecustomization.markdown) guide.
        * `defaultCertificateProfileName`: The default name of the certificate profile to use when enrolling certificates.
        * `defaultEndEntityProfileName`: The default name of the end entity profile to use when enrolling certificates.
        * `defaultCertificateAuthorityName`: The default name of the certificate authority to use when enrolling certificates.

    * If you want to configure the signer to enroll certificates using EST, the following field must be configured:
        * `defaultESTAlias`: The default alias of the EST configuration to use when enrolling certificates.

    Create a new ConfigMap resource using the following command:
    ```shell
    kubectl apply \
        --namespace ejbca-signer-system \
        -f ejbca-signer-config.yaml
    ```
   
    All fields in the ConfigMap can be overridden using annotations from the CSR at runtime. See the [Annotation Overrides for the EJBCA K8s CSR Signer](annotations.markdown) guide for more information.

4. If the EJBCA API is configured to use a self-signed certificate or with a certificate signed by an untrusted root, the CA certificate must be provided as a Kubernetes configmap.
   
    ```shell
    kubectl create configmap ejbca-ca-cert \
       --namespace ejbca-signer-system \
       --from-file=ca.crt
    ```

### 3. Installation from Helm Chart

The EJCBA K8s CSR Signer is installed using a Helm chart. The chart is available in the [EJCBA K8s CSR Signer Helm repository](https://keyfactor.github.io/ejbca-k8s-csr-signer/).

1. Add the Helm repository:
    
    ```bash
    helm repo add ejbca-k8s https://keyfactor.github.io/ejbca-k8s-csr-signer
    helm repo update
    ```

2. Then, install the chart:
    
    ```bash
    helm install ejbca-k8s-csr-signer ejbca-k8s/ejbca-k8s-csr-signer \
        --namespace ejbca-signer-system \
        --set image.repository=<your container registry>/keyfactor/ejbca-k8s-csr-signer \
        --set image.tag=<tag> \
        # --set image.pullPolicy=Never # Only required if using a local image \
        --set image.pullPolicy=Never \
        --set ejbca.credsSecretName=ejbca-credentials \
        --set ejbca.configMapName=ejbca-signer-config \
        # --set ejbca.caCertConfigmapName=ejbca-ca-cert # Only required if EJBCA API serves an untrusted certificate \
    ```

    1. Modifications can be made by overriding the default values in the `values.yaml` file with the `--set` flag. For example, to add an authorized signer name to the ClusterRole, run the following command:

        ```shell
        helm install ejbca-k8s-csr-signer ejbca-k8s/ejbca-k8s-csr-signer \
            --namespace ejbca-signer-system \
            --set image.repository=<your container registry>/keyfactor/ejbca-k8s-csr-signer \
            --set image.tag=<tag> \
            --set ejbca.signerNames[0]=internalsigner.com
        ```

    2. Modifications can also be made by modifying the `values.yaml` file directly. For example, to override the
    `signerNames` value, modify the `signerNames` value in the `values.yaml` file:

        ```yaml
        cat <<EOF > override.yaml
        image:
            repository: <your container registry>/keyfactor/ejbca-k8s-csr-signer
            pullPolicy: Never
            tag: "latest"
        ejbca:
            credsSecretName: ejbca-credentials
            configMapName: ejbca-signer-config
            caCertConfigmapName: ejbca-ca-cert
            signerNames:
                - internalsigner.com/cluster
        EOF
        ```

        Then, use the `-f` flag to specify the `values.yaml` file:
        
        ```yaml
        helm install ejbca-k8s-csr-signer ejbca-k8s/ejbca-k8s-csr-signer \
            --namespace ejbca-signer-system \
            -f override.yaml
        ```

###### :pushpin: Wildcards are **NOT** supported in the `signerNames` field. If you want to allow all signers, do not specify any signer names.

###### :pushpin: The EJBCA K8s CSR signer uses the `SelfSubjectAccessReview` API to determine if the user has permission to sign the CSR. If the user does not have permission, the signer will ignore the CSR.
 
### 4. Create a new CertificateSigningRequest resource with the provided sample
A [sample CSR object file](../sample/sample.yaml) is provided to getting started. Create a new CSR resource using the following command. The `request` field contains a Base64 encoded PKCS#10 PEM encoded certificate.
```shell
kubectl apply -f sample/sample.yaml
kubectl get csr
```
To enroll the CSR, it must be approved.
```shell
kubectl certificate approve ejbcaCsrTest
```
