package main

import (
	"context"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/internal/health"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/internal/signer"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/config"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/credential"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"os"
)

var (
	mainLog = logger.Register("Main")
)

func main() {
	// Serialize configuration
	serverConfig, err := config.LoadConfig()
	if err != nil {
		mainLog.Fatal(err)
		return
	}
	credentials, err := credential.LoadCredential()
	if err != nil {
		mainLog.Fatal(err)
		return
	}

	// Create a new EJBCA client using config
	ejbcaConfig := &ejbca.Config{
		CertificateFile:                 credentials.ClientCertPath,
		KeyFile:                         credentials.ClientKeyPath,
		KeyPassword:                     credentials.KeyPassword,
		DefaultCertificateProfileName:   serverConfig.DefaultCertificateProfileName,
		DefaultEndEntityProfileName:     serverConfig.DefaultEndEntityProfileName,
		DefaultCertificateAuthorityName: serverConfig.DefaultCertificateAuthorityName,
	}

	ejbcaFactory := ejbca.ClientFactory(credentials.Hostname, ejbcaConfig)
	if err != nil {
		mainLog.Fatal(err)
	}

	var ejbcaClient *ejbca.Client
	if serverConfig.UseEST {
		mainLog.Debugln("Creating EJBCA EST client")
		ejbcaClient, err = ejbcaFactory.NewESTClient(credentials.EJBCAUsername, credentials.EJBCAPassword)
		if err != nil {
			mainLog.Fatal(err)
		}
	} else {
		mainLog.Debugln("Creating EJBCA client")
		ejbcaClient, err = ejbcaFactory.NewEJBCAClient()
		if err != nil {
			mainLog.Fatal(err)
		}
	}

	k8sClient, err := NewInClusterClient()
	if err != nil {
		mainLog.Fatal(err)
	}
	mainLog.Info("Created in-cluster Kubernetes client")

	errChan := make(chan error)

	healthService := &health.ServiceHealthCheck{
		Addr: serverConfig.HealthCheckPort,
	}

	go func() {
		err = healthService.Serve()
		if err != nil {
			mainLog.Errorf("Failed to start health check service: %s", err.Error())
		}
		errChan <- err
	}()

	var name string
	if name = os.Getenv("SERVICE_NAME"); name == "" {
		name = "ejbca-csr-signer" // default name
	}

	ctx := context.Background()

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	csrInformer := informerFactory.Certificates().V1().CertificateSigningRequests()

	certificateController := signer.NewCertificateController(name, k8sClient, csrInformer, ejbcaClient)
	informerFactory.Start(ctx.Done())

	go certificateController.Run(ctx, 3)

	err = <-errChan

	mainLog.Fatal("EJBCA Certificate Controller closed; %s", err.Error())
}
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func NewInClusterClient() (*kubernetes.Clientset, error) {
	conf, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("create config failed: %v", err)
	}
	mainLog.Tracef("Got kubernetes config in cluster: %v", conf)

	client, err := kubernetes.NewForConfig(conf)
	if err != nil {
		mainLog.Errorf("Failed to create in-cluster Kubernetes client")
		return nil, fmt.Errorf("create kubernetes client failed: %v", err)
	}
	return client, nil
}
