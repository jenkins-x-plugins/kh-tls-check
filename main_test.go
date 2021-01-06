package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alecthomas/assert"
	acmev1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmFakeClient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"

	"github.com/jenkins-x/jx-helpers/v3/pkg/yamls"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestOptions_findErrors(t *testing.T) {

	var err error

	// getting the current namespace is found from a local kube config file
	err = os.Setenv("KUBECONFIG", filepath.Join("test_data", "test-config"))
	assert.NoError(t, err)

	o := Options{}

	tests := []struct {
		name      string
		namespace string
		want      []string
		wantErr   bool
	}{
		{name: "no_error", namespace: "", want: []string{}, wantErr: false},
		{name: "certificate_error", namespace: "", want: []string{"A bad thing happened"}, wantErr: false},
		{name: "certificate_error", namespace: "cheese", want: []string{"A bad thing happened"}, wantErr: false},
		{name: "certificate_error", namespace: "test", want: []string{}, wantErr: false},
		{name: "certificate_request_error", namespace: "", want: []string{"Waiting on certificate issuance from order jx/tls-pr-1956-2-gke-tls-jenkinsxlabs-com-s-wbnsn-458730623: \"pending\""}, wantErr: false},
		{name: "challenge_error", namespace: "", want: []string{"Waiting for DNS-01 challenge propagation: DNS record for \"pr-1956-2-gke-tls.jenkinsxlabs.com\" not yet propagated"}, wantErr: false},
		{name: "clusterissuer_error", namespace: "", want: []string{"A bad thing happened"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			os.Setenv(envVarTargetNamespace, tt.namespace)

			objects := loadDir(t, "cheese", filepath.Join("test_data", tt.name))
			o.cmClient = cmFakeClient.NewSimpleClientset(objects...)

			got, err := o.findErrors()
			if (err != nil) != tt.wantErr {
				t.Errorf("findErrors() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findErrors() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// LoadExtSecretFiles loads the given YAML files as external secrets for a test case
func loadFiles(t *testing.T, ns string, fileNames ...string) []runtime.Object {
	var objects []runtime.Object
	for _, path := range fileNames {
		require.FileExists(t, path)
		fileType := filepath.Base(path)

		switch fileType {

		case "certificateRequest.yaml":
			u := &v1.CertificateRequest{}
			err := yamls.LoadFile(path, u)
			require.NoError(t, err, "failed to load file %s", path)
			u.SetNamespace(ns)
			objects = append(objects, u)

		case "certificate.yaml":
			u := &v1.Certificate{}
			err := yamls.LoadFile(path, u)
			require.NoError(t, err, "failed to load file %s", path)
			u.SetNamespace(ns)
			objects = append(objects, u)

		case "challenge.yaml":
			u := &acmev1.Challenge{}
			err := yamls.LoadFile(path, u)
			require.NoError(t, err, "failed to load file %s", path)
			u.SetNamespace(ns)
			objects = append(objects, u)

		case "clusterIssuer.yaml":
			u := &v1.ClusterIssuer{}
			err := yamls.LoadFile(path, u)
			require.NoError(t, err, "failed to load file %s", path)
			u.SetNamespace(ns)
			objects = append(objects, u)

		case "issuer.yaml":
			u := &v1.Issuer{}
			err := yamls.LoadFile(path, u)
			require.NoError(t, err, "failed to load file %s", path)
			u.SetNamespace(ns)
			objects = append(objects, u)
		}

	}
	return objects
}

// LoadExtSecretDir loads the given YAML files in the given directory as external secrets for a test case
func loadDir(t *testing.T, ns, dir string) []runtime.Object {
	files, err := ioutil.ReadDir(dir)
	require.NoError(t, err, "failed to read dir %s", dir)
	var filesNames []string
	for _, f := range files {
		name := f.Name()
		if !f.IsDir() && strings.HasSuffix(name, ".yaml") {
			filesNames = append(filesNames, filepath.Join(dir, name))
		}
	}
	return loadFiles(t, ns, filesNames...)
}
