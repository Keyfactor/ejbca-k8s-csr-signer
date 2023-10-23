package controllers

import (
	"context"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/internal/signer"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/util"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errGetAuthSecret = errors.New("failed to get Secret containing Issuer credentials")
	errGetCaSecret   = errors.New("caSecretName specified a name, but failed to get Secret containing CA certificate")
)

type CertificateSigningRequestReconciler struct {
	client.Client
	Scheme                                  *runtime.Scheme
	SignerBuilder                           signer.Builder
	ClusterResourceNamespace                string
	Clock                                   clock.Clock
	CheckApprovedCondition                  bool
	CredsSecret, ConfigMap, CaCertConfigmap types.NamespacedName
}

func (c *CertificateSigningRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	reconcileLog := ctrl.LoggerFrom(ctx)

	c.SignerBuilder.Reset()

	// Get the CertificateSigningRequest
	var certificateSigningRequest certificates.CertificateSigningRequest
	if err = c.Get(ctx, req.NamespacedName, &certificateSigningRequest); err != nil {
		if err = client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		reconcileLog.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateSigningRequests that are not approved yet
	if c.CheckApprovedCondition && !util.IsCertificateRequestApproved(certificateSigningRequest) {
		reconcileLog.Info("CertificateSigningRequest has not been approved yet. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateSigningRequests that have already been signed
	if certificateSigningRequest.Status.Certificate != nil {
		reconcileLog.Info("CertificateSigningRequest has already been signed. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Always attempt to update the Ready condition
	defer func() {
		if updateErr := c.Status().Update(ctx, &certificateSigningRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// Get the credentials secret
	var creds corev1.Secret
	if err := c.Get(ctx, c.CredsSecret, &creds); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, c.CredsSecret.Name, err)
	}

	// Get the signer configuration
	var config corev1.ConfigMap
	if err := c.Get(ctx, c.ConfigMap, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, c.ConfigMap.Name, err)
	}

	// Get the CA certificate
	var root corev1.ConfigMap
	if c.CaCertConfigmap.Name != "" {
		// If the CA secret name is not specified, we will not attempt to retrieve it
		err = c.Get(ctx, c.CaCertConfigmap, &root)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetCaSecret, c.CaCertConfigmap.Name, err)
		}
	}

	// Apply the configuration to the signer builder
	c.SignerBuilder.
		WithContext(ctx).
		WithCredsSecret(creds).
		WithConfigMap(config).
		WithCACertConfigMap(root)

	// Validate that there were no issues with the configuration
	err = c.SignerBuilder.PreFlight()
	if err != nil {
		return ctrl.Result{}, err
	}

	// Sign the certificate
	leafAndChain, err := c.SignerBuilder.Build().Sign(certificateSigningRequest)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Update the certificate status
	certificateSigningRequest.Status.Certificate = leafAndChain

	return ctrl.Result{}, nil
}

func (c *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificates.CertificateSigningRequest{}).
		Complete(c)
}
