package credential

import (
    "fmt"
    "github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
    "gopkg.in/yaml.v3"
    "io/fs"
    "io/ioutil"
    "log"
    "os"
    "strings"
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
}

func LoadCredential() (*EJBCACredential, error) {
    creds := &EJBCACredential{}

    var fileList []fs.FileInfo

    credPath := os.Getenv("CREDENTIALS_FILE_DIR")

    fileList, err := ioutil.ReadDir(credPath)
    if err != nil {
        log.Fatal(err)
    }

    var buf []byte
    for _, file := range fileList {
        if strings.Contains(file.Name(), "yaml") && !file.IsDir() {
            credLog.Infof("Getting credentials from %s", file.Name())
            buf, err = ioutil.ReadFile(credPath + file.Name())
            if err != nil {
                credLog.Errorln("Ensure that credentials were properly injected into container:" + err.Error())
                return nil, err
            }
            if len(buf) <= 0 {
                return nil, fmt.Errorf("%s is empty. ensure that a secret was created called ejbca-credentials", file.Name())
            }

            credLog.Tracef("%s exists and contains %d bytes", file.Name(), len(buf))
            break
        }
    }

    err = yaml.Unmarshal(buf, &creds)
    if err != nil {
        return nil, err
    }

    credLog.Infoln("Successfully retrieved credentials.")

    // Directories are configured in deployment.yaml and exported
    // as environment variables. Build each path, but only if exported.
    // If these variables are not exported, client is configured to use EST.
    if clientCertDir := os.Getenv("CLIENT_CERT_DIR"); clientCertDir != "" {
        credLog.Infof("Looking in %s for client certificates", clientCertDir)

        fileList, err = ioutil.ReadDir(clientCertDir)
        if err != nil {
            log.Fatal(err)
        }

        var newCertBuf []byte

        for _, file := range fileList {
            if !file.IsDir() {
                buf, err = ioutil.ReadFile(clientCertDir + file.Name())
                if err == nil {
                    credLog.Infof("%s exists and contains %d bytes", file.Name(), len(buf))
                    newCertBuf = append(newCertBuf, buf...)
                } else {
                    credLog.Warnln(err)
                }
            }
        }

        err = ioutil.WriteFile("certkey.pem", newCertBuf, 6440)
        if err != nil {
            return nil, err
        }

        creds.ClientCertPath = "certkey.pem"

        credLog.Infoln("Successfully retrieved client certificate")
    }

    return creds, nil
}
