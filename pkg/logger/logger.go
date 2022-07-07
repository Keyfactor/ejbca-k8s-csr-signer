package logger

import (
	"github.com/sirupsen/logrus"
)

func Register(name string) *logrus.Entry {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	log.SetLevel(logrus.TraceLevel)
	return log.WithField("scope", name)
}
