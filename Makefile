VERSION=0.2.62

CHART_NAME = ejbca-csr-signer-0.1.0.tgz
HELM_NAMESPACE=ejbca
POD_NAME=ejbca-k8s
DOCKER_USERNAME=m8rmclarenkf
DOCKER_CONTAINER_NAME=ejbca-k8s-proxy
KUBE_SECRET_NAME=ejbca-credentials
BUILD_NUMBER_FILE=build-number.txt
CLIENT_CERT_PATH=certs/adminHaydenRoszell.pem
CLIENT_KEY_PATH=certs/adminHaydenRoszell.key
CA_CERT_PATH=certs/ejbcaCA.pem
CLIENT_SECRET_NAME=ejbca-client-cert
CA_CONFIGMAP_NAME=ejbca-ca-cert
CONFIGMAP_NAME=ejbca-config
APPLY_CONFIG_PATH=sample/sample.yaml
APPLY_NAME=ejbcaCsrTest

build: docker helm

cert:
	kubectl delete secret $(CLIENT_SECRET_NAME) -n $(HELM_NAMESPACE) || (echo nothing to delete)
	kubectl delete configmap -n $(HELM_NAMESPACE) $(CA_CONFIGMAP_NAME) || (echo nothing to delete)
	kubectl create secret tls $(CLIENT_SECRET_NAME) --cert=$(CLIENT_CERT_PATH) --key=$(CLIENT_KEY_PATH) -n $(HELM_NAMESPACE)
	kubectl create configmap -n $(HELM_NAMESPACE) $(CA_CONFIGMAP_NAME) --from-file $(CA_CERT_PATH)

clean:
	helm uninstall -n $(HELM_NAMESPACE) $(POD_NAME) || (echo nothing to clean)

creds:
	kubectl delete secret $(KUBE_SECRET_NAME) -n $(HELM_NAMESPACE) || (echo nothing to delete)
	kubectl create secret generic $(KUBE_SECRET_NAME) -n $(HELM_NAMESPACE) --from-file .\credentials\credentials.yaml

pods:
	kubectl -n $(HELM_NAMESPACE) get pods

logs:
	kubectl -n $(HELM_NAMESPACE) logs $(shell kubectl get pods --template '{{range .items}}{{.metadata.name}}{{end}}' -n $(HELM_NAMESPACE))

logf:
	kubectl -n $(HELM_NAMESPACE) logs $(shell kubectl get pods --template '{{range .items}}{{.metadata.name}}{{end}}' -n $(HELM_NAMESPACE)) -f

docker:
	docker build -t $(DOCKER_USERNAME)/$(DOCKER_CONTAINER_NAME):$(VERSION) .
	docker login
	docker push $(DOCKER_USERNAME)/$(DOCKER_CONTAINER_NAME):$(VERSION)

helm: clean
	helm package charts
	helm install -n $(HELM_NAMESPACE) $(POD_NAME) -f charts/values.yaml ./$(CHART_NAME) --set image.tag=$(VERSION)

apply:
	kubectl -n $(HELM_NAMESPACE) apply -f $(APPLY_CONFIG_PATH)
	kubectl -n $(HELM_NAMESPACE) get csr
	kubectl -n $(HELM_NAMESPACE) certificate approve $(APPLY_NAME)

remove:
	kubectl -n $(HELM_NAMESPACE) delete csr $(APPLY_NAME)