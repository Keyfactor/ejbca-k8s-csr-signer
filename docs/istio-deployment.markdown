# Deployment with Istio

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/ejbca-k8s-csr-signer?label=release)](https://github.com/keyfactor/ejbca-k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/ejbca-k8s-csr-signer.svg)]()

## Requirements
* EJBCA
    * [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)
* Docker (to build the container)
    * [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* Kubernetes (v1.19 +)
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/)
    * [Minikube](https://minikube.sigs.k8s.io/docs/start/)
    * [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
    * [Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
    * [Azure Kubernetes](https://azure.microsoft.com/en-us/products/kubernetes-service)
    * [Amazon EKS](https://aws.amazon.com/eks/)
    * [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine)
* Helm (to deploy CSR Controller)
    * [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

This guide will walk through configuring Istio to use the EJBCA K8s CSR Signer as an external certificate signing service. Once configured, Istio will provision workload certificates using the custom EJBCA CA configured in the EJBCA K8s CSR Signer.

For this tutorial, it's recommended that a distribution of Linux is used as the host operating system.

## Prepare Keyfactor EJBCA

Keyfactor EJBCA must be configured with an active CA and a certificate profile that can support signing of Istio workload certificates. Creating certificate profiles in EJBCA is accomplished via the adminweb interface, and the profile must support the following:

| Element                  | Requirement                                                                                    |
|--------------------------|------------------------------------------------------------------------------------------------|
| Public Key Algorithm     | Must support RSA                                                                               |
| Key Size                 | Must support 2048                                                                              |
| Signature Algorithm      | Must support SHA256 with RSA                                                                   |
| Subject DN               | None, Istio workload certificates will not have a subject DN.                                  |
| Subject Alternative Name | Must support at least 3 DNS Names, and the DNS Names must be allowed to not match the subject. |
| Key Usage                | Must support Digital Signature and Key Encipherment.                                           |
| Extended Key Usage       | Must support Server and Client Authentication.                                                 |

## 1. Deploy the EJBCA K8s CSR Signer

Follow the steps in the [Getting Started](getting-started.markdown) guide to build the container image and prepare the credentials and configuration. The `chainDepth` field in the `ejbca-signer-config.yaml` can be set to `1` since the CA chain will be provided to Istio via the IstioOperator.

## 2. Prepare Istio

Istio must not already be installed in your cluster, since modification of the Istio configuration is required.

1. Install Istioctl

    Install the Istio CLI, `istioctl`, by running the following commands:

    ```shell
    curl -L https://istio.io/downloadIstio | sh -
    cd istio-<version>
    export PATH=$PWD/bin:$PATH
    ```

    Or navigate to the Istio [release page](https://github.com/istio/istio/releases/) and download the latest release for your host OS.

2. Download and store the CA Chain of the EJBCA CA represented by the default EST alias or the default CA name.

    * If the default EST alias is used, the CA chain can be downloaded with the following commands:

        ```shell
        curl https://<hostname to EJBCA>/.well-known/est/<EST Alias>/cacerts -o cacerts.p7.b64
        openssl base64 -in cacerts.p7.b64 -out cacerts.p7 -d
        openssl pkcs7 -inform DER -in cacerts.p7 -print_certs -out cacerts.pem
        ```

    * If the default CA name is used, the CA chain must be downloaded from the EJBCA Admin GUI.

        1. Navigate to the EJBCA RA and log in.
        2. Navigate to the CA Certificates and CRLs page.
        3. Click the PEM link next to the CA name.

    Export the root certificates of the EJBCA CA.

    ```shell
    export EJBCA_ROOT_CERTS=$(cat <path to PEM encoded CA cert chain> | sed 's/^/          /')
    ```

3. Deploy Istio with the `keyfactor.com/bookinfo` and `keyfactor.com/istio-system` signers.

    The signer names can be modified according do your cluster's needs, but you _must_ ensure that the signer names match the signer names configured in the `ejbca.signerNames` in the EJBCA K8s CSR Signer Helm chart. By default, no signer names are configured in the EJBCA K8s CSR Signer, all signer names are in scope.

    ```yaml
    cat <<EOF > ./ejbca-istio.yaml
    apiVersion: install.istio.io/v1alpha1
    kind: IstioOperator
    spec:
      values:
        pilot:
          env:
            EXTERNAL_CA: ISTIOD_RA_KUBERNETES_API
      meshConfig:
        defaultConfig:
          proxyMetadata:
            ISTIO_META_CERT_SIGNER: istio-system
        caCertificates:
          - pem: |
    $EJBCA_ROOT_CERTS
            certSigners:
              - keyfactor.com/istio-system
          - pem: |
    $EJBCA_ROOT_CERTS
            certSigners:
              - keyfactor.com/bookinfo
      components:
        pilot:
          k8s:
            env:
              - name: CERT_SIGNER_DOMAIN
                value: keyfactor.com
              - name: PILOT_CERT_PROVIDER
                value: k8s.io/keyfactor.com/istio-system
            overlays:
              - apiVersion: apps/v1
                kind: Deployment
                name: istiod
                patches:
                  - path: spec.template.spec.containers.[name:discovery].args
                    value:
                      - "discovery"
                      - "--log_output_level=default:debug"
              - kind: ClusterRole
                name: istiod-clusterrole-istio-system
                patches:
                  - path: rules[-1]
                    value: |
                      apiGroups:
                      - certificates.k8s.io
                      resourceNames:
                      - keyfactor.com/bookinfo
                      - keyfactor.com/istio-system
                      resources:
                      - signers
                      verbs:
                      - approve
    EOF
    istioctl install --skip-confirmation -f ./ejbca-istio.yaml
    ```

## 3. Deploy the Bookinfo demo application

1. Create a namespace for the Bookinfo demo application.
    ```shell
    kubectl create ns bookinfo
    ```

    Label the namespace with the `istio-injection=enabled` label to enable automatic sidecar injection.
    ```shell
    kubectl label namespace bookinfo istio-injection=enabled
    ```

2. Enforce strict mTLS for the `bookinfo` namespace.

    ```yaml
    cat <<EOF | kubectl apply -f -
    apiVersion: security.istio.io/v1beta1
    kind: PeerAuthentication
    metadata:
      name: default
      namespace: bookinfo
    spec:
      mtls:
        mode: STRICT
    EOF
    ```

3. Deploy an Istio ProxyConfig in the `bookinfo` namespace to define a signer for workloads in the `bookinfo` namespace.

    ```yaml
    cat <<EOF | kubectl apply -f -
    apiVersion: networking.istio.io/v1beta1
    kind: ProxyConfig
    metadata:
      name: bookinfopc
      namespace: bookinfo
    spec:
      environmentVariables:
        ISTIO_META_CERT_SIGNER: bookinfo
    EOF
    ```

4. Deploy the demo book application.
    
    ```shell
    kubectl -n bookinfo apply -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml
    ```

    Verify that all services and pods are correctly defined and running.

    ```shell
    kubectl -n bookinfo get pods
    kubectl -n bookinfo get services
    ```

    Verify that the Bookinfo application is running.
    ```shell
    kubectl -n bookinfo exec "$(kubectl -n bookinfo get pod -l app=ratings -o jsonpath='{.items[0].metadata.name}')" -c ratings -- curl -sS productpage:9080/productpage
    ```

    Observe the mTLS certificate and chain.
    ```shell
    kubectl -n bookinfo exec "$(kubectl -n bookinfo get pod -l app=ratings -o jsonpath='{.items[0].metadata.name}')" -c istio-proxy -- openssl s_client -showcerts -connect productpage.bookinfo:9080
    ```

6. Apply the Istio Gateway and VirtualService to expose the Bookinfo application.
    
    ```shell
    kubectl -n bookinfo apply -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/networking/bookinfo-gateway.yaml
    ```

    Confirm that the gateway was created.

    ```shell
    kubectl get gateway -n bookinfo
    ```

7. Determine the Ingress IP and Port of the Istio Gateway.
    
    ```shell
    export INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [ -z "$INGRESS_HOST" ]; then
        export INGRESS_HOST=localhost
    fi
    export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
    export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
    ```

8. Confirm that the Bookinfo application is running.

    ```shell
    curl -s http://${GATEWAY_URL}/productpage | grep -o "<title>.*</title>"
    echo "http://${GATEWAY_URL}/productpage"
    ```
