package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/utils"
	"go.step.sm/crypto/pemutil"
	v1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

const (
	rootOnlyKey                   = "autocert.step.sm/root-only"
	admissionWebhookAnnotationKey = "autocert.step.sm/name"
	admissionWebhookStatusKey     = "autocert.step.sm/status"
	durationWebhookStatusKey      = "autocert.step.sm/duration"
	firstAnnotationKey            = "autocert.step.sm/init-first"
	bootstrapperOnlyAnnotationKey = "autocert.step.sm/bootstrapper-only"
	sansAnnotationKey             = "autocert.step.sm/sans"
	volumeMountPath               = "/var/run/autocert.step.sm"
)

// Config options for the autocert admission controller.
type Config struct {
	Address                         string           `yaml:"address"`
	Service                         string           `yaml:"service"`
	LogFormat                       string           `yaml:"logFormat"`
	CaURL                           string           `yaml:"caUrl"`
	CertLifetime                    string           `yaml:"certLifetime"`
	Bootstrapper                    corev1.Container `yaml:"bootstrapper"`
	Renewer                         corev1.Container `yaml:"renewer"`
	CertsVolume                     corev1.Volume    `yaml:"certsVolume"`
	SATokenVolume                   corev1.Volume    `yaml:"saTokenVolume"`
	RestrictCertificatesToNamespace bool             `yaml:"restrictCertificatesToNamespace"`
	ClusterDomain                   string           `yaml:"clusterDomain"`
	InternalDomain                  string           `yaml:"internalDomain"`
	RootCAPath                      string           `yaml:"rootCAPath"`
	ProvisionerPasswordPath         string           `yaml:"provisionerPasswordPath"`
}

// GetAddress returns the address set in the configuration, defaults to ":4443"
// if it's not specified.
func (c Config) GetAddress() string {
	if c.Address != "" {
		return c.Address
	}

	return ":4443"
}

// GetServiceName returns the service name set in the configuration, defaults to
// "autocert" if it's not specified.
func (c Config) GetServiceName() string {
	if c.Service != "" {
		return c.Service
	}

	return "autocert"
}

// GetClusterDomain returns the Kubernetes cluster domain, defaults to
// "cluster.local" if not specified in the configuration.
func (c Config) GetClusterDomain() string {
	if c.ClusterDomain != "" {
		return c.ClusterDomain
	}

	return "cluster.local"
}

// GetRootCAPath returns the root CA path in the configuration, defaults to
// "STEPPATH/certs/root_ca.crt" if it's not specified.
func (c Config) GetRootCAPath() string {
	if c.RootCAPath != "" {
		return c.RootCAPath
	}

	return pki.GetRootCAPath()
}

// GetProvisionerPasswordPath returns the path to the provisioner password,
// defaults to "/home/step/password/password" if not specified in the
// configuration.
func (c Config) GetProvisionerPasswordPath() string {
	if c.ProvisionerPasswordPath != "" {
		return c.ProvisionerPasswordPath
	}

	return "/home/step/password/password"
}

// PatchOperation represents a RFC6902 JSONPatch Operation
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// RFC6901 JSONPath Escaping -- https://tools.ietf.org/html/rfc6901
func escapeJSONPath(path string) string {
	// Replace`~` with `~0` then `/` with `~1`. Note that the order
	// matters otherwise we'll turn a `/` into a `~/`.
	path = strings.Replace(path, "~", "~0", -1)
	path = strings.Replace(path, "/", "~1", -1)
	return path
}

func loadConfig(file string) (*Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// mkBootstrapper generates a bootstrap container based on the template defined in Config. It
// generates a new bootstrap token and mounts it, along with other required configuration, as
// environment variables in the returned bootstrap container.
func mkBootstrapper(config *Config, podName string, rootOnly bool, commonName, duration, namespace string) (corev1.Container, error) {
	b := config.Bootstrapper

	// Generate CA fingerprint
	crt, err := pemutil.ReadCertificate(config.GetRootCAPath())
	if err != nil {
		return b, errors.Wrap(err, "CA fingerprint")
	}
	sum := sha256.Sum256(crt.Raw)
	fingerprint := strings.ToLower(hex.EncodeToString(sum[:]))

	if rootOnly {
		b.Env = append(b.Env, corev1.EnvVar{
			Name:  "ROOT_ONLY",
			Value: "true",
		})
	}

	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "COMMON_NAME",
		Value: commonName,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "DURATION",
		Value: duration,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "STEP_CA_URL",
		Value: config.CaURL,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "STEP_FINGERPRINT",
		Value: fingerprint,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "STEP_NOT_AFTER",
		Value: config.CertLifetime,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "POD_NAME",
		Value: podName,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "NAMESPACE",
		Value: namespace,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "CLUSTER_DOMAIN",
		Value: config.ClusterDomain,
	})

	b.TTY = true

	return b, nil
}

// mkRenewer generates a new renewer based on the template provided in Config.
func mkRenewer(config *Config, podName, commonName, namespace string) corev1.Container {
	r := config.Renewer
	r.Env = append(r.Env, corev1.EnvVar{
		Name:  "STEP_CA_URL",
		Value: config.CaURL,
	})
	r.Env = append(r.Env, corev1.EnvVar{
		Name:  "COMMON_NAME",
		Value: commonName,
	})
	r.Env = append(r.Env, corev1.EnvVar{
		Name:  "POD_NAME",
		Value: podName,
	})
	r.Env = append(r.Env, corev1.EnvVar{
		Name:  "NAMESPACE",
		Value: namespace,
	})
	r.Env = append(r.Env, corev1.EnvVar{
		Name:  "CLUSTER_DOMAIN",
		Value: config.ClusterDomain,
	})
	return r
}

func removeInitContainers() (ops PatchOperation) {
	return PatchOperation{
		Op:   "remove",
		Path: "/spec/initContainers",
	}
}

func addContainers(existing, new []corev1.Container, path string) (ops []PatchOperation) {
	if len(existing) == 0 {
		return []PatchOperation{
			{
				Op:    "add",
				Path:  path,
				Value: new,
			},
		}
	}

	for _, add := range new {
		ops = append(ops, PatchOperation{
			Op:    "add",
			Path:  path + "/-",
			Value: add,
		})
	}

	return ops
}

func addVolumes(existing, new []corev1.Volume, path string) (ops []PatchOperation) {
	if len(existing) == 0 {
		return []PatchOperation{
			{
				Op:    "add",
				Path:  path,
				Value: new,
			},
		}
	}

	for _, add := range new {
		ops = append(ops, PatchOperation{
			Op:    "add",
			Path:  path + "/-",
			Value: add,
		})
	}
	return ops
}

func addCertsVolumeMount(volumeName string, containers []corev1.Container, containerType string, first bool) (ops []PatchOperation) {
	volumeMount := corev1.VolumeMount{
		Name:      volumeName,
		MountPath: volumeMountPath,
		ReadOnly:  true,
	}

	add := 0
	if first {
		add = 1
	}

	for i, container := range containers {
		if len(container.VolumeMounts) == 0 {
			ops = append(ops, PatchOperation{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%v/volumeMounts", containerType, i+add),
				Value: []corev1.VolumeMount{volumeMount},
			})
		} else {
			ops = append(ops, PatchOperation{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%v/volumeMounts/-", containerType, i+add),
				Value: volumeMount,
			})
		}
	}
	return ops
}

func addAnnotations(existing, new map[string]string) (ops []PatchOperation) {
	if len(existing) == 0 {
		return []PatchOperation{
			{
				Op:    "add",
				Path:  "/metadata/annotations",
				Value: new,
			},
		}
	}
	for k, v := range new {
		if existing[k] == "" {
			ops = append(ops, PatchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + escapeJSONPath(k),
				Value: v,
			})
		} else {
			ops = append(ops, PatchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + escapeJSONPath(k),
				Value: v,
			})
		}
	}
	return ops
}

// patch produces a list of patches to apply to a pod to inject a certificate. In particular,
// we patch the pod in order to:
//  - Mount the `certs` volume in existing containers and initContainers defined in the pod
//  - Add the autocert-renewer as a container (a sidecar)
//  - Add the autocert-bootstrapper as an initContainer
//  - Add the `certs` volume definition
//  - Annotate the pod to indicate that it's been processed by this controller
// The result is a list of serialized JSONPatch objects (or an error).
func patch(pod *corev1.Pod, namespace string, config *Config) ([]byte, error) {
	var ops []PatchOperation

	name := pod.ObjectMeta.GetName()
	if name == "" {
		name = pod.ObjectMeta.GetGenerateName()
	}

	annotations := pod.ObjectMeta.GetAnnotations()
	rootOnly := annotations[rootOnlyKey] == "true"
	commonName := annotations[admissionWebhookAnnotationKey]
	first := strings.EqualFold(annotations[firstAnnotationKey], "true")
	bootstrapperOnly := strings.EqualFold(annotations[bootstrapperOnlyAnnotationKey], "true")
	duration := annotations[durationWebhookStatusKey]
	renewer := mkRenewer(config, name, commonName, namespace)
	bootstrapper, err := mkBootstrapper(config, name, rootOnly, commonName, duration, namespace)
	if err != nil {
		return nil, err
	}

	if first {
		if len(pod.Spec.InitContainers) > 0 {
			ops = append(ops, removeInitContainers())
		}

		initContainers := append([]corev1.Container{bootstrapper}, pod.Spec.InitContainers...)
		ops = append(ops, addContainers([]corev1.Container{}, initContainers, "/spec/initContainers")...)
	} else {
		ops = append(ops, addContainers(pod.Spec.InitContainers, []corev1.Container{bootstrapper}, "/spec/initContainers")...)
	}

	ops = append(ops, addCertsVolumeMount(config.CertsVolume.Name, pod.Spec.Containers, "containers", false)...)
	ops = append(ops, addCertsVolumeMount(config.CertsVolume.Name, pod.Spec.InitContainers, "initContainers", first)...)
	if !rootOnly && !bootstrapperOnly {
		ops = append(ops, addContainers(pod.Spec.Containers, []corev1.Container{renewer}, "/spec/containers")...)
	}
	ops = append(ops, addVolumes(pod.Spec.Volumes, []corev1.Volume{config.CertsVolume}, "/spec/volumes")...)
	ops = append(ops, addVolumes(pod.Spec.Volumes, []corev1.Volume{config.SATokenVolume}, "/spec/volumes")...)
	ops = append(ops, addAnnotations(pod.Annotations, map[string]string{admissionWebhookStatusKey: "injected"})...)

	return json.Marshal(ops)
}

// shouldMutate checks whether a pod is subject to mutation by this admission controller. A pod
// is subject to mutation if it's annotated with the `admissionWebhookAnnotationKey` and if it
// has not already been processed (indicated by `admissionWebhookStatusKey` set to `injected`).
// If the pod requests a certificate with a subject matching a namespace other than its own
// and restrictToNamespace is true, then shouldMutate will return a validation error
// that should be returned to the client.
func shouldMutate(metadata *metav1.ObjectMeta, namespace string, clusterDomain string, restrictToNamespace bool) (bool, error) {
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	// Only mutate if the object is annotated appropriately (annotation key set) and we haven't
	// mutated already (status key isn't set).
	if annotations[admissionWebhookStatusKey] == "injected" {
		return false, nil
	}

	if annotations[rootOnlyKey] == "true" {
		return true, nil
	}

	if annotations[admissionWebhookAnnotationKey] == "" {
		return false, nil
	}

	if !restrictToNamespace {
		return true, nil
	}

	subject := strings.Trim(annotations[admissionWebhookAnnotationKey], ".")

	err := fmt.Errorf("subject \"%s\" matches a namespace other than \"%s\" and is not permitted. This check can be disabled by setting restrictCertificatesToNamespace to false in the autocert-config ConfigMap", subject, namespace)

	if strings.HasSuffix(subject, ".svc") && !strings.HasSuffix(subject, fmt.Sprintf(".%s.svc", namespace)) {
		return false, err
	}

	if strings.HasSuffix(subject, fmt.Sprintf(".svc.%s", clusterDomain)) && !strings.HasSuffix(subject, fmt.Sprintf(".%s.svc.%s", namespace, clusterDomain)) {
		return false, err
	}

	return true, nil
}

// mutate takes an `AdmissionReview`, determines whether it is subject to mutation, and returns
// an appropriate `AdmissionResponse` including patches or any errors that occurred.
func mutate(review *v1.AdmissionReview, config *Config) *v1.AdmissionResponse {
	ctxLog := log.WithField("uid", review.Request.UID)

	request := review.Request
	var pod corev1.Pod
	if err := json.Unmarshal(request.Object.Raw, &pod); err != nil {
		ctxLog.WithField("error", err).Error("Error unmarshaling pod")
		return &v1.AdmissionResponse{
			Allowed: false,
			UID:     request.UID,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	ctxLog = ctxLog.WithFields(log.Fields{
		"kind":         request.Kind,
		"operation":    request.Operation,
		"name":         pod.Name,
		"generateName": pod.GenerateName,
		"namespace":    request.Namespace,
		"user":         request.UserInfo,
	})

	mutationAllowed, validationErr := shouldMutate(&pod.ObjectMeta, request.Namespace, config.GetClusterDomain(), config.RestrictCertificatesToNamespace)

	if validationErr != nil {
		ctxLog.WithField("error", validationErr).Info("Validation error")
		return &v1.AdmissionResponse{
			Allowed: false,
			UID:     request.UID,
			Result: &metav1.Status{
				Message: validationErr.Error(),
			},
		}
	}

	if !mutationAllowed {
		ctxLog.WithField("annotations", pod.Annotations).Info("Skipping mutation")
		return &v1.AdmissionResponse{
			Allowed: true,
			UID:     request.UID,
		}
	}

	patchBytes, err := patch(&pod, request.Namespace, config)
	if err != nil {
		ctxLog.WithField("error", err).Error("Error generating patch")
		return &v1.AdmissionResponse{
			Allowed: false,
			UID:     request.UID,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	ctxLog.WithField("patch", string(patchBytes)).Info("Generated patch")
	return &v1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		UID:     request.UID,
		PatchType: func() *v1.PatchType {
			pt := v1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Errorf("Usage: %s <config>\n", os.Args[0])
		os.Exit(1)
	}

	config, err := loadConfig(os.Args[1])
	if err != nil {
		panic(err)
	}

	log.SetOutput(os.Stdout)
	if config.LogFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if config.LogFormat == "text" {
		log.SetFormatter(&log.TextFormatter{})
	}

	log.WithFields(log.Fields{
		"config": config,
	}).Info("Loaded config")

	provisionerName := os.Getenv("PROVISIONER_NAME")
	provisionerKid := os.Getenv("PROVISIONER_KID")
	log.WithFields(log.Fields{
		"provisionerName": provisionerName,
		"provisionerKid":  provisionerKid,
	}).Info("Loaded provisioner configuration")

	password, err := utils.ReadPasswordFromFile(config.GetProvisionerPasswordPath())
	if err != nil {
		panic(err)
	}

	provisioner, err := ca.NewProvisioner(
		provisionerName, provisionerKid, config.CaURL, password,
		ca.WithRootFile(config.GetRootCAPath()))
	if err != nil {
		log.Errorf("Error loading provisioner: %v", err)
		os.Exit(1)
	}
	log.WithFields(log.Fields{
		"name": provisioner.Name(),
		"kid":  provisioner.Kid(),
	}).Info("Loaded provisioner")

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		log.Errorf("$NAMESPACE not set")
		os.Exit(1)
	}

	name := fmt.Sprintf("%s.%s.svc", config.GetServiceName(), namespace)
	token, err := provisioner.Token(name)
	if err != nil {
		log.WithField("error", err).Errorf("Error generating bootstrap token during controller startup")
		os.Exit(1)
	}
	log.WithField("name", name).Infof("Generated bootstrap token for controller")

	// make sure to cancel the renew goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := ca.BootstrapServer(ctx, token, &http.Server{
		Addr: config.GetAddress(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				log.Debug("/healthz")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, "ok")
				return
			}

			if r.URL.Path == "/token" {
				log.Debug("/token")

				token, status, err := handleTokenRequest(ctx, provisioner, r, config)
				if err != nil {
					log.WithError(err).Error("error occurred while processing token request")
					w.WriteHeader(status)
					return
				}

				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, token)
				return
			}

			if r.URL.Path != "/mutate" {
				log.WithField("path", r.URL.Path).Error("Bad Request: 404 Not Found")
				http.NotFound(w, r)
				return
			}

			var body []byte
			if r.Body != nil {
				if data, err := ioutil.ReadAll(r.Body); err == nil {
					body = data
				}
			}
			if len(body) == 0 {
				log.Error("Bad Request: 400 (Empty Body)")
				http.Error(w, "Bad Request (Empty Body)", http.StatusBadRequest)
				return
			}

			contentType := r.Header.Get("Content-Type")
			if contentType != "application/json" {
				log.WithField("Content-Type", contentType).Error("Bad Request: 415 (Unsupported Media Type)")
				http.Error(w, fmt.Sprintf("Bad Request: 415 Unsupported Media Type (Expected Content-Type 'application/json' but got '%s')", contentType), http.StatusUnsupportedMediaType)
				return
			}

			var response *v1.AdmissionResponse
			review := v1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       "AdmissionReview",
				},
			}
			if _, _, err := deserializer.Decode(body, nil, &review); err != nil {
				log.WithFields(log.Fields{
					"body":  body,
					"error": err,
				}).Error("Can't decode body")
				response = &v1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Message: err.Error(),
					},
				}
			} else {
				response = mutate(&review, config)
			}

			resp, err := json.Marshal(v1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       "AdmissionReview",
				},
				Response: response,
			})
			if err != nil {
				log.WithFields(log.Fields{
					"uid":   review.Request.UID,
					"error": err,
				}).Info("Marshal error")
				http.Error(w, fmt.Sprintf("Marshal Error: %v", err), http.StatusInternalServerError)
			} else {
				log.WithFields(log.Fields{
					"uid":      review.Request.UID,
					"response": string(resp),
				}).Info("Returning review")
				if _, err := w.Write(resp); err != nil {
					log.WithFields(log.Fields{
						"uid":   review.Request.UID,
						"error": err,
					}).Info("Write error")
				}
			}
		}),
	}, ca.VerifyClientCertIfGiven())
	if err != nil {
		panic(err)
	}

	log.Info("Listening on", config.GetAddress(), "...")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}

// handleTokenRequest authorizes the request by sending a TokenReview with the service account token to apiserver,
// then it will generate a token with the pod IP as part of the SANs and send it back to the bootstrapper
func handleTokenRequest(ctx context.Context, provisioner *ca.Provisioner, r *http.Request, config *Config) (string, int, error) {
	var token string

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return token, http.StatusUnauthorized, errors.New("missing authorization header")
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return token, http.StatusBadRequest, errors.New("Authorization header format must be Bearer {token}")
	}

	saToken := authHeaderParts[1]

	c, err := getK8sClient()
	if err != nil {
		return token, http.StatusInternalServerError, err
	}

	review := authv1.TokenReview{Spec: authv1.TokenReviewSpec{
		Token:     saToken,
		Audiences: []string{"autocert"},
	}}
	resp, err := c.AuthenticationV1().TokenReviews().Create(ctx, &review, metav1.CreateOptions{})
	if err != nil {
		return token, http.StatusInternalServerError, err
	}

	if !resp.Status.Authenticated {
		return token, http.StatusUnauthorized, errors.New("invalid sa token")
	}

	saTokenParsed, err := parseSAToken(saToken)
	if err != nil {
		return token, http.StatusInternalServerError, err
	}

	token, err = generateToken(provisioner, saTokenParsed.K8s.Namespace, saTokenParsed.K8s.Pod.Name, config.ClusterDomain, config.InternalDomain)
	if err != nil {
		return token, http.StatusInternalServerError, err
	}

	return token, http.StatusOK, nil
}

func parseSAToken(saTokenString string) (saToken, error) {
	token := saToken{}

	parts := strings.Split(saTokenString, ".")
	seg := parts[1]
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	segment, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return token, err
	}

	decoder := json.NewDecoder(bytes.NewBuffer(segment))
	err = decoder.Decode(&token)
	if err != nil {
		return token, err
	}

	return token, nil
}

type saToken struct {
	K8s struct {
		Namespace string `json:"namespace,omitempty"`
		Pod       struct {
			Name string `json:"name,omitempty"`
		} `json:"pod,omitempty"`
	} `json:"kubernetes.io,omitempty"`
}

func generateToken(provisioner *ca.Provisioner, ns string, podName string, domain string, internalDomain string) (string, error) {
	c, err := getK8sClient()
	if err != nil {
		return "", err
	}

	var pod *corev1.Pod
	var counter int
	timeout, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	err = wait.PollImmediateUntil(2*time.Second, func() (done bool, err error) {
		log.WithField("counter", counter).Info("fetching pod IP")
		counter++
		var e error
		pod, e = c.CoreV1().Pods(ns).Get(timeout, podName, metav1.GetOptions{})
		if e != nil {
			log.WithError(e).Error("failed to fetch pod IP")
			return false, nil
		}

		return pod.Status.PodIP != "", nil
	}, timeout.Done())
	cancelFunc()
	if err != nil {
		return "", err
	}

	annotations := pod.ObjectMeta.GetAnnotations()
	commonName := annotations[admissionWebhookAnnotationKey]

	splitCommonNameFn := func(c rune) bool {
		return c == '.'
	}

	segments := strings.FieldsFunc(commonName, splitCommonNameFn)
	if len(segments) <= 0 {
		return "", errors.Errorf("invalid common name: %s", commonName)
	}

	svcName := segments[0]
	timeout, cancelFunc = context.WithTimeout(context.Background(), 10*time.Second)
	service, err := c.CoreV1().Services(ns).Get(timeout, svcName, metav1.GetOptions{})
	cancelFunc()
	if err != nil {
		return "", err
	}

	svcSans := []string{svcName,
		fmt.Sprintf("%s.%s", svcName, ns),
		fmt.Sprintf("%s.%s.svc", svcName, ns),
		fmt.Sprintf("%s.%s.svc.%s", svcName, ns, domain),
		service.Spec.ClusterIP}
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		ing := service.Status.LoadBalancer.Ingress
		if len(ing) <= 0 {
			log.Warnf("external IP address of the LB service [%s] not available, skipping", svcName)
		} else {
			svcSans = append(svcSans, ing[0].IP)
		}

		if internalDomain != "" {
			svcSans = append(svcSans, fmt.Sprintf("%s.%s", svcName, internalDomain))
		}
	}

	splitFn := func(c rune) bool {
		return c == ','
	}

	sans := strings.FieldsFunc(annotations[sansAnnotationKey], splitFn)
	if len(sans) == 0 {
		sans = []string{commonName}
	}
	sans = append(sans, svcSans...)
	sans = append(sans, pod.Status.PodIP, "localhost", "127.0.0.1")
	log.Info("sans:", sans)

	token, err := provisioner.Token(commonName, sans...)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate token")
	}

	return token, nil
}

func getK8sClient() (*kubernetes.Clientset, error) {
	kc, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(kc)
	if err != nil {
		return nil, err
	}

	return kubeClient, nil
}
