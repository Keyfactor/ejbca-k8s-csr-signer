package signer

import (
	"context"
	"fmt"
	"github.com/Keyfactor/ejbca-k8s-csr-signer/pkg/logger"
	"time"

	"github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
	"golang.org/x/time/rate"

	certificates "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	certificatesinformers "k8s.io/client-go/informers/certificates/v1"
	clientset "k8s.io/client-go/kubernetes"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

var (
	signerLog = logger.Register("CertificateSigner")
)

type CertificateController struct {
	// name is an identifier for this particular controller instance.
	name string

	kubeClient clientset.Interface

	csrLister  certificateslisters.CertificateSigningRequestLister
	csrsSynced cache.InformerSynced

	handler func(context.Context, *certificates.CertificateSigningRequest) error

	queue workqueue.RateLimitingInterface

	ejbcaClient *ejbca.Client
}

func NewCertificateController(
	name string,
	kubeClient clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	ejbcaClient *ejbca.Client,
) *CertificateController {
	signerLog.Infof("Creating new Certificate Controller called '%s'", name)

	// Send events to the apiserver
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	cc := &CertificateController{
		name:       name,
		kubeClient: kubeClient,
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
			// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "certificate"),
		ejbcaClient: ejbcaClient,
	}

	// Manage the addition/update of certificate requests
	csrInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			signerLog.Infof("Adding certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldCSR := old.(*certificates.CertificateSigningRequest)
			signerLog.Infof("Updating certificate request %s", oldCSR.Name)
			cc.enqueueCertificateRequest(new)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					signerLog.Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					signerLog.Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			signerLog.Infof("Deleting certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
	})

	cc.handler = cc.handleRequests
	cc.csrLister = csrInformer.Lister()
	cc.csrsSynced = csrInformer.Informer().HasSynced

	signerLog.Tracef("Finished configuring Certificate Controller called '%s'", name)
	return cc
}

// Run the main goroutine responsible for watching and syncing jobs.
func (cc *CertificateController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer cc.queue.ShutDown()

	signerLog.Infof("Starting certificate controller %q", cc.name)
	defer signerLog.Infof("Shutting down certificate controller %q", cc.name)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	if !cache.WaitForNamedCacheSync(fmt.Sprintf("certificate-%s", cc.name), timeoutCtx.Done(), cc.csrsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, cc.worker, time.Second)
	}

	signerLog.Infof("Certificate controller started for %s", cc.name)

	<-ctx.Done()
}

// worker runs a thread that dequeues CSRs, handles them, and marks them done.
func (cc *CertificateController) worker(ctx context.Context) {
	for cc.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (cc *CertificateController) processNextWorkItem(ctx context.Context) bool {
	cKey, quit := cc.queue.Get()
	if quit {
		return false
	}
	defer cc.queue.Done(cKey)

	if err := cc.syncFunc(ctx, cKey.(string)); err != nil {
		cc.queue.AddRateLimited(cKey)
		if _, ignorable := err.(ignorableError); !ignorable {
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with : %v", cKey, err))
		} else {
			signerLog.Infof("Sync %v failed with : %v", cKey, err)
		}
		return true
	}

	cc.queue.Forget(cKey)
	return true

}

func (cc *CertificateController) enqueueCertificateRequest(obj interface{}) {
	// Kubernetes controller_utils uses DeletionHandlingMetaNamespaceKeyFunc
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	cc.queue.Add(key)
}

func (cc *CertificateController) syncFunc(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		signerLog.Debugf("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()
	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
		signerLog.Debugf("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if len(csr.Status.Certificate) > 0 {
		// no need to do anything because it already has a cert
		return nil
	}

	// need to operate on a copy so we don't mutate the csr in the shared cache
	csr = csr.DeepCopy()
	return cc.handler(ctx, csr)
}

// IgnorableError returns an error that we shouldn't handle (i.e. log) because
// it's spammy and usually user error. Instead we will log these errors at a
// higher log level. We still need to throw these errors to signal that the
// sync should be retried.
func IgnorableError(s string, args ...interface{}) ignorableError {
	return ignorableError(fmt.Sprintf(s, args...))
}

type ignorableError string

func (e ignorableError) Error() string {
	return string(e)
}
