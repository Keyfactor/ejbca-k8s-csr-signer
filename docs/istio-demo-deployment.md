# Demonstration Deployment with Istio

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

For this demonstration, it's recommended that a distribution of Linux is used as the host
operating system, since the installation of Istio is easier.

| :memo:        | This guide is based on the [Istio Getting Started](https://istio.io/latest/docs/setup/getting-started/) guide and the [Istio External PKI](https://istio.io/latest/docs/tasks/security/cert-management/custom-ca-k8s/) guide |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## Getting Started
1. Configure a new EJBCA EST profile. todo explain some crazy stuff Sven did to get this working
2. Deploy the EJBCA K8s CSR Controller
   1. Clone the repository
    ```shell
    $ git clone https://github.com/Keyfactor/ejbca-k8s-csr-signer.git
    ```
   2. Create a new K8s namespace for the CSR proxy.
    ```shell
    $ kubectl create namespace ejbca
    ```
   3. Create a new K8s secret containing required credentials for operating with the CSR proxy. A [sample credentials file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml) is provided as a reference. Ensure that the hostname and 
    ```shell
    $ kubectl -n ejbca create secret generic ejbca-credentials --from-file ./credentials/credentials.yaml
    ```
   4. Deploy the EJBCA K8s CSR Controller using Helm
    ```shell
    $ helm package charts
    $ helm install -n ejbca ejbca-k8s -f charts/values.yaml ./ejbca-csr-signer-0.1.0.tgz
    ```
   5. Open a new terminal, and run the following command to track the activity of the CSR controller.
    ```shell
    $ kubectl -n ejbca logs $(kubectl get pods --template '{{range .items}}{{.metadata.name}}{{end}}' -n ejbca) -f
    ```
3. Install Istio (based on [Getting Started with Istio](https://istio.io/latest/docs/setup/getting-started/))
   1. Run the following command to download the installation for your OS, or navigate to the Istio [release page](https://github.com/istio/istio/releases/tag/1.14.1) and download the release according to your host OS.
    ```shell
    $ curl -L https://istio.io/downloadIstio | sh -
    $ cd istio-1.14.1
    ```
   3. Add a namespace label to instruct Istio to automatically inject the Envoy sidecar proxy.
    ```shell
    $ kubectl label namespace default istio-injection=enabled
    ```
4. Load the root CA certificate of the CA used by the EST alias into a K8s secret. 
   1. Ensure that the certificate is in PEM format, and that it is Base64 encoded. This can be accomplished by running the following commands:
    ```shell
    $ curl https://<hostname to EJBCA>/.well-known/est/<EST Alias>/cacerts -o cacerts.p7.b64
    $ openssl base64 -in cacerts.p7.b64 -out cacerts.p7 -d
    $ openssl pkcs7 -inform DER -in cacerts.p7 -print_certs -out cacerts.pem
    ```
   2. Create a K8s secret containing the root CA certificate
    ```shell
    $ touch external-ca-secret.yaml
    ```
    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: external-ca-cert
      namespace: istio-system
    data:
      root-cert.pem: <base64 encoded CA chain from above>
    ```
   3. Apply the secret
    ```shell
    $ kubectl apply -f external-ca-secret.yaml
    ```
5. Deploy Istio with the 'demo' configuration profile
   1. Create K8s deployment file
    ```shell
    $ touch istio.yaml
    ```
   2. Populate it with the following contents:
    ```yaml
    apiVersion: install.istio.io/v1alpha1
    kind: IstioOperator
    spec:
      components:
        pilot:
          k8s:
            env:
              # Indicate to Istiod that we use an external signer
              - name: EXTERNAL_CA
                value: ISTIOD_RA_KUBERNETES_API
              # Indicate to Istiod the external k8s Signer Name
              - name: K8S_SIGNER
                value: example.com/foo
            overlays:
              # Amend ClusterRole to add permission for istiod to approve certificate signing by custom signer
              - kind: ClusterRole
                name: istiod-clusterrole-istio-system
                patches:
                  - path: rules[-1]
                    value: |
                      apiGroups:
                      - certificates.k8s.io
                      resourceNames:
                      - example.com/foo
                      resources:
                      - signers
                      verbs:
                      - approve
              - kind: Deployment
                name: istiod
                patches:
                  - path: spec.template.spec.containers[0].volumeMounts[-1]
                    value: |
                      # Mount external CA certificate into Istiod
                      name: external-ca-cert
                      mountPath: /etc/external-ca-cert
                      readOnly: true
                  - path: spec.template.spec.volumes[-1]
                    value: |
                      name: external-ca-cert
                      secret:
                        secretName: external-ca-cert
                        optional: true
    ```
   3. Apply the configuration
    ```shell
    $ istioctl install --set profile=demo -f ./istio.yaml
    ```
6. Deploy the demo book application
  ```shell
  $ kubectl create ns bookinfo
  $ kubectl apply -f <(istioctl kube-inject -f samples/bookinfo/platform/kube/bookinfo.yaml) -n bookinfo
  ```
7. Verify that the custom certificates are installed correctly
   1. Dump the running pods in the `bookinfo` namespace
    ```shell
    $ kubectl get pods -n bookinfo
    ```
   2. Get the certificate chain and CA root certificate used by the Istio proxies for mTLS.
    ```shell
    $ istioctl pc secret <pod-name> -n bookinfo -o json > proxy_secret
    ```
8. Open the bookinfo application to outside traffic
```shell
$ kubectl apply -f samples/bookinfo/networking/bookinfo-gateway.yaml -n bookinfo
```
9. Verify that the pods are communicating correctly
   1. In another terminal window, start a Minikube tunnel that sends traffic to the Istio Ingress gateway.
```shell
$ minikube tunnel
```
2. Set the ingress host, ports, and gateway
```shell
$ export INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
$ export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
$ export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
$ export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
$ echo "http://$GATEWAY_URL/productpage"
```
   3. Navigate to the link outputted by the last command and confirm that the Bookinfo product page is displayed.