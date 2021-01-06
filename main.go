package main

import (
	"context"
	"fmt"
	"os"

	v1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1"

	"github.com/jenkins-x/jx-kube-client/v3/pkg/kubeclient"

	"github.com/Comcast/kuberhealthy/v2/pkg/checks/external/checkclient"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmClient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"

	"github.com/jenkins-x/jx-logging/v3/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	dynamicClient dynamic.Interface
	cmClient      cmClient.Interface
}

const envVarTargetNamespace = "TARGET_NAMESPACE"

func main() {

	log.Logger().Infof("starting kh-tls-check health checks")

	o, err := newOptions()
	if err != nil {
		log.Logger().Fatalf("failed to validate options: %v", err)
		return
	}

	kherrors, err := o.findErrors()
	if err != nil {
		log.Logger().Fatalf("failed to find certmanager errors: %v", err)
	}

	if len(kherrors) == 0 {
		err = checkclient.ReportSuccess()
		if err != nil {
			log.Logger().Fatalf("failed to report success status %v", err)
		}
	} else {
		err = checkclient.ReportFailure(kherrors)
		if err != nil {
			log.Logger().Fatalf("failed to report failure status %v", err)
		}
	}

	log.Logger().Infof("successfully reported")
}

func (o Options) findErrors() ([]string, error) {
	kherrors := []string{}

	namespace := os.Getenv(envVarTargetNamespace)
	if namespace == "" {
		// it is the same value but we are being explicit that we are listing pods in all namespaces
		namespace = corev1.NamespaceAll
	}

	// first lets check clusterissuers and issuers
	clusterIssuerErrors, err := o.GetClusterIssuerErrors(namespace, metav1.ListOptions{})
	if err != nil {
		return kherrors, errors.Wrapf(err, "failed to find cluster issuer errors")
	}
	if clusterIssuerErrors != "" {
		kherrors = append(kherrors, clusterIssuerErrors)
	}

	issuerErrors, err := o.GetIssuerErrors(namespace, metav1.ListOptions{})
	if err != nil {
		return kherrors, errors.Wrapf(err, "failed to find issuer errors")
	}
	if issuerErrors != "" {
		kherrors = append(kherrors, issuerErrors)
	}

	// next look for any certificate request errors
	certificateRequestErrors, err := o.GetCertificateRequestsErrors(namespace, metav1.ListOptions{})
	if err != nil {
		return kherrors, errors.Wrapf(err, "failed to find certificate request errors")
	}
	if certificateRequestErrors != "" {
		kherrors = append(kherrors, certificateRequestErrors)
	}

	// next look for any challenge errors
	challengeErrors, err := o.GetChallengeErrors(namespace, metav1.ListOptions{})
	if err != nil {
		return kherrors, errors.Wrapf(err, "failed to find challenge errors")
	}
	if challengeErrors != "" {
		kherrors = append(kherrors, challengeErrors)
	}

	// lastly look for any certificate errors
	certificateErrors, err := o.GetCertificateErrors(namespace, metav1.ListOptions{})
	if err != nil {
		return kherrors, errors.Wrapf(err, "failed to find certificate errors")
	}
	if certificateErrors != "" {
		kherrors = append(kherrors, certificateErrors)
	}
	log.Logger().Infof("errors: %v", kherrors)
	return kherrors, nil
}

func newOptions() (*Options, error) {
	o := Options{}
	var err error
	f := kubeclient.NewFactory()
	cfg, err := f.CreateKubeConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get kubernetes config")
	}

	if o.cmClient == nil {
		o.cmClient, err = cmClient.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a certmanager client")
		}
	}

	return &o, nil
}

func (o Options) GetCertificateRequestsErrors(ns string, listOptions metav1.ListOptions) (string, error) {

	crs, err := o.cmClient.CertmanagerV1().CertificateRequests(ns).List(context.TODO(), listOptions)
	if err != nil {
		return "", errors.Wrapf(err, "failed to list certificate requests in namespace %s", ns)
	}
	for _, cert := range crs.Items {
		if len(cert.Status.Conditions) > 0 {
			lastCondition := cert.Status.Conditions[0]
			if lastCondition.Status == cmmeta.ConditionFalse {
				if lastCondition.Message != "" {
					return lastCondition.Message, nil
				}
				return fmt.Sprintf("certificate request %s in namespace %s not ready and no messasge found", cert.Name, cert.Namespace), nil
			}
		}
	}
	return "", nil
}

func (o Options) GetCertificateErrors(ns string, listOptions metav1.ListOptions) (string, error) {

	certs, err := o.cmClient.CertmanagerV1().Certificates(ns).List(context.TODO(), listOptions)
	if err != nil {
		return "", errors.Wrapf(err, "failed to list certificates in namespace %s", ns)
	}
	for _, cert := range certs.Items {
		if len(cert.Status.Conditions) > 0 {
			lastCondition := cert.Status.Conditions[0]
			if lastCondition.Status == cmmeta.ConditionFalse {
				if lastCondition.Message != "" {
					return lastCondition.Message, nil
				}
				return fmt.Sprintf("certificate %s in namespace %s not ready and no messasge found", cert.Name, cert.Namespace), nil
			}
		}
	}
	return "", nil
}

func (o Options) GetIssuerErrors(ns string, listOptions metav1.ListOptions) (string, error) {

	issuers, err := o.cmClient.CertmanagerV1().Issuers(ns).List(context.TODO(), listOptions)
	if err != nil {
		return "", errors.Wrapf(err, "failed to list issuers in namespace %s", ns)
	}
	for _, cert := range issuers.Items {
		if len(cert.Status.Conditions) > 0 {
			lastCondition := cert.Status.Conditions[0]
			if lastCondition.Status == cmmeta.ConditionFalse {
				if lastCondition.Message != "" {
					return lastCondition.Message, nil
				}
				return fmt.Sprintf("issuer %s in namespace %s not ready and no messasge found", cert.Name, cert.Namespace), nil
			}
		}
	}
	return "", nil
}

func (o Options) GetClusterIssuerErrors(ns string, listOptions metav1.ListOptions) (string, error) {

	issuers, err := o.cmClient.CertmanagerV1().ClusterIssuers().List(context.TODO(), listOptions)
	if err != nil {
		return "", errors.Wrapf(err, "failed to list issuers in namespace %s", ns)
	}
	for _, cert := range issuers.Items {
		if len(cert.Status.Conditions) > 0 {
			lastCondition := cert.Status.Conditions[0]
			if lastCondition.Status == cmmeta.ConditionFalse {
				if lastCondition.Message != "" {
					return lastCondition.Message, nil
				}
				return fmt.Sprintf("issuer %s in namespace %s not ready and no messasge found", cert.Name, cert.Namespace), nil
			}
		}
	}
	return "", nil
}

func (o Options) GetChallengeErrors(ns string, listOptions metav1.ListOptions) (string, error) {

	challenges, err := o.cmClient.AcmeV1().Challenges(ns).List(context.TODO(), listOptions)
	if err != nil {
		return "", errors.Wrapf(err, "failed to list issuers in namespace %s", ns)
	}
	for _, challange := range challenges.Items {
		switch challange.Status.State {
		case v1.Valid:
			continue
		case v1.Ready:
			continue
		}
		if challange.Status.Reason != "" {
			return challange.Status.Reason, nil
		}
		return fmt.Sprintf("challange %s in namespace %s not ready or valid and no reason found", challange.Name, challange.Namespace), nil

	}
	return "", nil
}
