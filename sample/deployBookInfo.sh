#!/bin/sh

kubectl delete ns bookinfo
kubectl create ns bookinfo
kubectl apply -f $(istioctl kube-inject -f samples/bookinfo/platform/kube/bookinfo.yaml) -n bookinfo
kubectl apply -f $(istioctl kube-inject -f samples/bookinfo/networking/bookinfo-gateway.yaml) -n bookinfo
kubectl apply -n bookinfo -f strict.yaml
export INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
echo "http://$GATEWAY_URL/productpage"
export PRODUCTPAGE_POD=$(kubectl get pod -n bookinfo -l app=productpage -o jsonpath={.items..metadata.name})
echo $PRODUCTPAGE_POD
alias productpagecerts="kubectl exec $PRODUCTPAGE_POD -c istio-proxy -n bookinfo -- openssl s_client -showcerts -connect reviews:9080"