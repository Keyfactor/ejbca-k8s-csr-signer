package config

import (
	"fmt"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type ServerConfig struct {
	HealthCheckPort                 string `yaml:"healthcheckPort"`
	DefaultCertificateProfileName   string `yaml:"defaultCertificateProfileName"`
	DefaultEndEntityProfileName     string `yaml:"defaultEndEntityProfileName"`
	DefaultCertificateAuthorityName string `yaml:"defaultCertificateAuthorityName"`
	UseEST                          bool   `yaml:"useEST"`
	DefaultESTAlias                 string `yaml:"defaultESTAlias"`
}

var (
	configLog = logger.Register("Config")
)

func LoadConfig() (*ServerConfig, error) {
	config := &ServerConfig{}

	file := "./config/config.yaml"
	configLog.Infof("Getting configuration from %s", file)

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		configLog.Errorln("Ensure that a configmap was created called ejbca-config")
		return nil, err
	}

	if len(buf) <= 0 {
		return nil, fmt.Errorf("%s is empty. ensure that a configmap was created called ejbca-config", file)
	}

	configLog.Tracef("%s exists and contains %d bytes", file, len(buf))

	err = yaml.Unmarshal(buf, &config)
	if err != nil {
		return nil, err
	}

	configLog.Infof("Successfully retrieved configuration: \n %#v\n", config)

	return config, nil
}
