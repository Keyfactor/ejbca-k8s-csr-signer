package health

import (
	"fmt"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
	"github.com/valyala/fasthttp"
)

var (
	healthLog = logger.Register("CertificateSigner-Handler")
)

// ServiceHealthCheck create a health check service
type ServiceHealthCheck struct {
	Addr string
}

// Serve start listen health check
func (s *ServiceHealthCheck) Serve() error {
	address := fmt.Sprintf("[::]:%s", s.Addr)
	healthLog.Infof("Starting health check service at: %v", address)
	if err := fasthttp.ListenAndServe(address, fasthttp.CompressHandler(s.requestHandler)); err != nil {
		healthLog.Fatalf("Error in ListenAndServe: %s", err)
		return fmt.Errorf("Error in ListenAndServe: %s", err)
	}
	return nil
}

func (s *ServiceHealthCheck) requestHandler(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	_, err := fmt.Fprintf(ctx, "OK!")
	if err != nil {
		return
	}
	ctx.SetContentType("text/plain; charset=utf8")
}
