# Configure Vault with K8s to retrieve client certificate in a more secure manner

## Requirements
* EJBCA
	* [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)
* Docker (to build the container)
	* [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* Kubernetes (v1.19 +)
	* [Kubernetes](https://kubernetes.io/docs/tasks/tools/) or [Minikube](https://minikube.sigs.k8s.io/docs/start/)
* Helm (to deploy CSR Controller)
	* [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

## Overview and Rationale
By default, `ejbca-k8s-csr-signer` uses a K8s tls secret to store and inject a client certificate for authentication to EJBCA.
This poses a security risk because secret objects can be retrieved and displayed in plaintext. HashiCorp Vault offers a
K8s native solution to security concerns of this nature using the Vault Kubernetes Sidecar Injector. This solution enables
`ejbca-k8s-csr-signer` to remain unaware of Vault by first running the `vault-agent-init` container. Access to secrets
in Vault by K8s are configured via K8s service accounts and namespace scope.

## Configuration

### Install the Vault Helm Chart
HashiCorp recommends that Vault is deployed on K8s using the [Helm chart](https://www.vaultproject.io/docs/platform/k8s/helm).
```shell
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault hashicorp/vault --set "server.dev.enabled=true"
kubectl get pods
```
The Vault pod and Vault Agent Injector are deployed into the default namespace.

| :exclamation:  | Production deployments should omit `--set "server.dev.enabled=true"` to deploy Vault in a production-ready manner. Setting this value authenticates the local `vault` container CLI which makes it easy to experiment with.  |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

### Configure Vault and Create Secret
Connect to the Vault shell and enable the v1 KV secrets engine.
```shell
kubectl exec -it vault-0 -- /bin/sh
vault secrets enable -path=internal kv
```

Next, set a secret in Vault using the v1 KV engine. Omitted was the creation of `tls.crt` and `tls.key` files containing the client certificate keypair. 
Shell history can easily be retrieved, so configuring the KV secret should be done in a methodical manner. Key names in this step are 
unimportant, and the client certificate and private key may be configured in the same key-value tag.
```shell
vault kv put secret/ejbca cert=@tls.crt key=@tls.key
```
Optionally, verify that the secret is defined at the configured path.
```shell
vault kv get secret/ejbca 
```

### Configure Kubernetes Authentication
Vault provides a Kubernetes authentication method that allows clients to authenticate using a Kubernetes Service Account Token, provided to each pod during creation. First, enable this authentication method.
```shell
vault auth enable kubernetes
```
Vault accepts service tokens from any client in the cluster, which is verified by querying the K8s token review endpoint.
The `$KUBERNETES_PORT_443_TCP_ADDR` environment variable is injected into each pod in the cluster and references the cluster IP address of the Kubernetes host.
```shell
vault write auth/kubernetes/config kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443"
```
To enable clients to read the secret data defined at `secret/ejbca`, Vault `read` abilities must be granted for the path `secret/data/ejbca`. Configure this access with a Vault `policy`.
```shell
vault policy write ejbca-cred - <<EOF
path "secret/data/ejbca" {
  capabilities = ["read"]
}
EOF
```

Create a Kubernetes authentication role named `ejbca-cred`. Vault will now authenticate pods using a service account called `ejbca-cred` in the `ejbca` namespace using the Vault `ejbca-cred` role name.
```shell
vault write auth/kubernetes/role/ejbca-cred \
	bound_service_account_names=ejbca-cred \
	bound_service_account_namespaces=ejbca \
	policies=ejbca-cred \
	ttl=24h
```
If a name other than `ejbca-cred` is used for the policy and authentication role, `ejbca-k8s-csr-signer` must be configured to use 
this role using `--set ejbca.vault.roleName=<role name>`. Additionally, if `serviceAccount.create=true` (recommended), Helm 
will also create the K8s service account and link it to the deployment.

Exit out of the interactive shell.
```shell
exit
```

### Deploy `ejbca-k8s-csr-signer`
Finally, deploy `ejbca-k8s-csr-signer` with vault enabled.
```shell
helm upgrade --install ejbca-csr-signer ejbca-csr-signer \
  --repo https://github.com/Keyfactor/ejbca-k8s-csr-signer \
  --namespace ejbca \
  --set ejbca.useEST=false \
  --set ejbca.vault.enabled=true \
  --set ejbca.vault.roleName="ejbca-cred"
```