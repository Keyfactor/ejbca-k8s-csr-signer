# Demonstration Deployment with Istio

## Requirements
* EJBCA
    * [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)
* Docker (to build the container)
    * [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* Kubernetes (v1.19 +)
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/) or [Minikube](https://minikube.sigs.k8s.io/docs/start/)
* Helm (to deploy CSR Controller)
    * [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

For this demonstration, it's recommended that a distribution of Linux is used as the host
operating system, since the installation of Istio is easier.

## Configure EJBCA and retrieve CA certificate chain
1. Configure an EST profile in EJBCA.
2. Download CA certificate and chain
```shell
curl https://<hostname to EJBCA>/.well-known/est/<EST Alias>/cacerts -o cacerts.p7.b64
openssl base64 -in cacerts.p7.b64 -out cacerts.p7 -d
openssl pkcs7 -inform DER -in cacerts.p7 -print_certs -out cacerts.pem
```

## Configure K8s Environment
1. Install Minikube using the [installation steps](https://minikube.sigs.k8s.io/docs/start/)
   1. For example:
   ```shell
   curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
   sudo install minikube-linux-amd64 /usr/local/bin/minikube
   ```
2. Install CA certificate from above in `~/.minikube/files/etc/external-ca-cert/root-cert.pem`
```shell
mkdir -p ~/.minikube/files/etc/external-ca-cert
cp <path to PEM encoded CA certificate chain> ~/.minikube/files/etc/external-ca-cert/root-cert.pem
```
3. Start Minikube
```shell
minikube start
```

## Getting Started
1. Deploy the EJBCA K8s CSR Controller
   1. Clone the repository
    ```shell
    git clone https://github.com/Keyfactor/ejbca-k8s-csr-signer.git
    ```
   2. Create a new K8s namespace for the CSR proxy.
    ```shell
    kubectl create namespace ejbca
    ```
   3. Create a new K8s secret containing required credentials for operating with the CSR proxy. A [sample credentials file](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/credentials/sample.yaml) is provided as a reference. Ensure that the hostname and 
    ```shell
    kubectl -n ejbca create secret generic ejbca-credentials --from-file ./credentials/credentials.yaml
    ```
   4. Deploy the EJBCA K8s CSR Controller using Helm
    ```shell
    helm package charts
    helm install -n ejbca ejbca-k8s -f charts/values.yaml ./ejbca-csr-signer-0.1.0.tgz
    ```
   5. Open a new terminal, and run the following command to track the activity of the CSR controller.
    ```shell
    kubectl -n ejbca logs $(kubectl get pods --template '{{range .items}}{{.metadata.name}}{{end}}' -n ejbca) -f
    ```
2. Install Istio
   1. Run the following command to download the installation for your OS, or navigate to the Istio [release page](https://github.com/istio/istio/releases/tag/1.14.1) and download the release according to your host OS.
    ```shell
    curl -L https://istio.io/downloadIstio | sh -
    cd istio-1.14.1
    export PATH=$PWD/bin:$PATH
    istioctl install --set profile=demo -y
    ```
3. Load the root CA certificate of the CA used by the EST alias into a K8s secret. 
   1. Encode the certificate from above in Base64 and remove newline characters.
   ```shell
   base64 <path to PEM encoded CA cert chain> | tr -d \\n
   ```
   2. Create a K8s secret containing the root CA certificate
    ```shell
    touch external-ca-secret.yaml
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
    kubectl apply -f external-ca-secret.yaml
    ```
4. Deploy Istio with the 'demo' configuration profile
   1. Create K8s deployment file
    ```shell
    touch istio.yaml
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
    istioctl install --set profile=demo -f ./istio.yaml
    ```
5. Deploy the demo book application. An install script can be found in `sample/deployBookInfo.sh`
  ```shell
  kubectl create ns bookinfo
  kubectl apply -f <(istioctl kube-inject -f samples/bookinfo/platform/kube/bookinfo.yaml) -n bookinfo
  ```
6. Open bookinfo gateway to open traffic to outside
```shell
kubectl apply -f <(istioctl kube-inject -f samples/bookinfo/networking/bookinfo-gateway.yaml) -n bookinfo
```
7. In another terminal window, start a Minikube tunnel that sends traffic to the Istio Ingress gateway.
```shell
minikube tunnel
```
8. Set the ingress host, ports, and gateway
```shell
export INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
echo "http://$GATEWAY_URL/productpage"
```
9. Navigate to the link outputted by the last command and confirm that the Bookinfo product page is displayed.
