package main

import (
	"errors"
	"flag"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/internal/controllers"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/internal/signer"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/util"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var clusterResourceNamespace string
	var printVersion bool
	var disableApprovedCheck bool

	var credsSecretName, configMapName, caCertConfigmapName string

	flag.StringVar(&credsSecretName, "credential-secret-name", "", "The name of the secret containing the EJBCA credentials")
	flag.StringVar(&configMapName, "configmap-name", "", "The name of the configmap containing the signer configuration")
	flag.StringVar(&caCertConfigmapName, "ca-cert-configmap-name", "", "The name of the configmap containing the root CAs of the EJBCA API server")

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&clusterResourceNamespace, "cluster-resource-namespace", "", "The namespace for secrets in which cluster-scoped resources are found.")
	flag.BoolVar(&printVersion, "version", false, "Print version to stdout and exit")
	flag.BoolVar(&disableApprovedCheck, "disable-approved-check", false,
		"Disables waiting for CertificateRequests to have an approved condition before signing.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if clusterResourceNamespace == "" {
		var err error
		clusterResourceNamespace, err = util.GetInClusterNamespace()
		if err != nil {
			if errors.Is(err, errors.New("not running in-cluster")) {
				setupLog.Error(err, "please supply --cluster-resource-namespace")
			} else {
				setupLog.Error(err, "unexpected error while getting in-cluster Namespace")
			}
			os.Exit(1)
		}
	}

	if credsSecretName == "" {
		setupLog.Error(errors.New("please supply --credential-secret-name"), "")
		os.Exit(1)
	}

	if configMapName == "" {
		setupLog.Error(errors.New("please supply --configmap-name"), "")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b68cef23.keyfactor.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	credsSecret := types.NamespacedName{
		Namespace: clusterResourceNamespace,
		Name:      credsSecretName,
	}
	configMap := types.NamespacedName{
		Namespace: clusterResourceNamespace,
		Name:      configMapName,
	}
	caCertConfigmap := types.NamespacedName{
		Namespace: clusterResourceNamespace,
		Name:      caCertConfigmapName,
	}

	ejbcaSignerBuilder, err := signer.NewEjbcaSignerBuilder()
	if err != nil {
		setupLog.Error(err, "unable to create EJBCA signer")
		os.Exit(1)
	}

	if err = (&controllers.CertificateSigningRequestReconciler{
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		SignerBuilder:            ejbcaSignerBuilder,
		ClusterResourceNamespace: clusterResourceNamespace,
		Clock:                    clock.RealClock{},
		CheckApprovedCondition:   !disableApprovedCheck,
		CredsSecret:              credsSecret,
		ConfigMap:                configMap,
		CaCertConfigmap:          caCertConfigmap,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateSigningRequest")
		os.Exit(1)
	}

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
