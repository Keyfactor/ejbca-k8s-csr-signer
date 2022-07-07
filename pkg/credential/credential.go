package credential

import (
	"fmt"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
)

var (
	credLog = logger.Register("Credential")
)

type EJBCACredential struct {
	// Hostname to EJBCA server
	Hostname string `yaml:"hostname"`

	// Password used to protect key, if it's encrypted according to RFC 1423. Leave blank if private key
	// is not encrypted.
	KeyPassword    string `yaml:"keyPassword"`
	EJBCAUsername  string `yaml:"ejbcaUsername"`
	EJBCAPassword  string `yaml:"ejbcaPassword"`
	ClientCertPath string
	ClientKeyPath  string
}

func LoadCredential() (*EJBCACredential, error) {
	creds := &EJBCACredential{}

	file := "./credentials/credentials.yaml"
	credLog.Infof("Getting credentials from %s", file)

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		credLog.Errorln("Ensure that a secret was created called ejbca-credentials")
		return nil, err
	}

	if len(buf) <= 0 {
		return nil, fmt.Errorf("%s is empty. ensure that a secret was created called ejbca-credentials", file)
	}

	err = yaml.Unmarshal(buf, &creds)
	if err != nil {
		return nil, err
	}

	// Directories are configured in deployment.yaml and exported
	// as environment variables. Build each path, but only if exported.
	// If these variables are not exported, client is likely using EST, or the
	// EJBCA server certificate was signed by a trusted CA.
	if client := os.Getenv("CLIENT_CERT_DIR"); client != "" {
		// Client certificate stored using tls secret; Kubernetes stores these secrets
		// as tls.crt and tls.key.
		certPath := client + "/tls.crt"
		keyPath := client + "/tls.key"

		buf, err = ioutil.ReadFile(certPath)
		if err == nil {
			credLog.Infof("%s exists and contains %d bytes", certPath, len(buf))
			creds.ClientCertPath = certPath
		} else {
			credLog.Warnln(err)
		}

		buf, err = ioutil.ReadFile(keyPath)
		if err == nil {
			credLog.Tracef("%s exists and contains %d bytes", keyPath, len(buf))
			creds.ClientKeyPath = keyPath
		} else {
			credLog.Warnln(err)
		}
	}

	credLog.Infoln("Successfully retrieved credentials.")

	return creds, nil
}
