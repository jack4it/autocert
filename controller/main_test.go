package main

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetClusterDomain(t *testing.T) {
	c := Config{}
	if c.GetClusterDomain() != "cluster.local" {
		t.Errorf("cluster domain should default to cluster.local, not: %s", c.GetClusterDomain())
	}

	c.ClusterDomain = "mydomain.com"
	if c.GetClusterDomain() != "mydomain.com" {
		t.Errorf("cluster domain should default to cluster.local, not: %s", c.GetClusterDomain())
	}
}

func TestShouldMutate(t *testing.T) {
	testCases := []struct {
		description string
		subject     string
		namespace   string
		expected    bool
	}{
		{"full cluster domain", "test.default.svc.cluster.local", "default", true},
		{"full cluster domain wrong ns", "test.default.svc.cluster.local", "kube-system", false},
		{"left dots get stripped", ".test.default.svc.cluster.local", "default", true},
		{"left dots get stripped wrong ns", ".test.default.svc.cluster.local", "kube-system", false},
		{"right dots get stripped", "test.default.svc.cluster.local.", "default", true},
		{"right dots get stripped wrong ns", "test.default.svc.cluster.local.", "kube-system", false},
		{"dots get stripped", ".test.default.svc.cluster.local.", "default", true},
		{"dots get stripped wrong ns", ".test.default.svc.cluster.local.", "kube-system", false},
		{"partial cluster domain", "test.default.svc.cluster", "default", true},
		{"partial cluster domain wrong ns is still allowed because not valid hostname", "test.default.svc.cluster", "kube-system", true},
		{"service domain", "test.default.svc", "default", true},
		{"service domain wrong ns", "test.default.svc", "kube-system", false},
		{"two part domain", "test.default", "default", true},
		{"two part domain different ns", "test.default", "kube-system", true},
		{"one hostname", "test", "default", true},
		{"no subject specified", "", "default", false},
		{"three part not cluster", "test.default.com", "kube-system", true},
		{"four part not cluster", "test.default.svc.com", "kube-system", true},
		{"five part not cluster", "test.default.svc.cluster.com", "kube-system", true},
		{"six part not cluster", "test.default.svc.cluster.local.com", "kube-system", true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			mutationAllowed, validationErr := shouldMutate(&metav1.ObjectMeta{
				Annotations: map[string]string{
					admissionWebhookAnnotationKey: testCase.subject,
				},
			}, testCase.namespace, "cluster.local", true)
			if mutationAllowed != testCase.expected {
				t.Errorf("shouldMutate did not return %t for %s", testCase.expected, testCase.description)
			}
			if testCase.subject != "" && mutationAllowed == false && validationErr == nil {
				t.Errorf("shouldMutate should return validation error for invalid hostname")
			}
		})
	}
}

func TestShouldMutateNotRestrictToNamespace(t *testing.T) {
	mutationAllowed, _ := shouldMutate(&metav1.ObjectMeta{
		Annotations: map[string]string{
			admissionWebhookAnnotationKey: "test.default.svc.cluster.local",
		},
	}, "kube-system", "cluster.local", false)
	if mutationAllowed == false {
		t.Errorf("shouldMutate should return true even with a wrong namespace if restrictToNamespace is false.")
	}
}

func Test_mkRenewer(t *testing.T) {
	type args struct {
		config     *Config
		podName    string
		commonName string
		namespace  string
	}
	tests := []struct {
		name string
		args args
		want corev1.Container
	}{
		{"ok", args{&Config{CaURL: "caURL", ClusterDomain: "clusterDomain"}, "podName", "commonName", "namespace"}, corev1.Container{
			Env: []corev1.EnvVar{
				{Name: "STEP_CA_URL", Value: "caURL"},
				{Name: "COMMON_NAME", Value: "commonName"},
				{Name: "POD_NAME", Value: "podName"},
				{Name: "NAMESPACE", Value: "namespace"},
				{Name: "CLUSTER_DOMAIN", Value: "clusterDomain"},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mkRenewer(tt.args.config, tt.args.podName, tt.args.commonName, tt.args.namespace); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mkRenewer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSATokenClaimsParsing(t *testing.T) {
	saTokenString := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjdCRTJXZmI2Y3RrWjNsM0pXYjVGaFdGUjRiTVJyelIyUXNOc05nV1Zic0UifQ.eyJhdWQiOlsiZmFjdG9ycyJdLCJleHAiOjE2MjE1MzgyNjEsImlhdCI6MTYyMTUzNzY2MSwiaXNzIjoiXCJha3MtZGV2LXRydi1rOHMtd3VzMi04YmMzN2JlMy5oY3Aud2VzdHVzMi5hem1rOHMuaW9cIiIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiY2RzLWFwaS1leHBlcmltZW50IiwicG9kIjp7Im5hbWUiOiJ0b2tlbi1jbGllbnQtZGRmZmQ2NDg5LXByc2I1IiwidWlkIjoiZjI4YWMxZmEtNTUyNy00OWViLWIxN2YtMDYyNGI1MjJkM2RhIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZWZhdWx0IiwidWlkIjoiZGY4NWZkZmQtYWE4OS00YzlkLTg5ZDItNTlhODNkYmM1OTI4In19LCJuYmYiOjE2MjE1Mzc2NjEsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpjZHMtYXBpLWV4cGVyaW1lbnQ6ZGVmYXVsdCJ9.hWuZ-FxQPRQchmaSlCgz9SpEg30JxNJyO7mid-cIkuM14sPvhyLSj0JYFXpe94Xjq0j8cl-JI8sF4Mpag7d2r4v66eRGynWufMY1VRP18Leq_axOdabjs1GFn_l57A48w8F0F6bYj2XeTq7K4IH0P_lV1lgf2tQIuaMbCZc3OsZKI6eQbLh7j3-sbGuP_qtTyngXIRKon1gS1g5JLn25n5FBHuyO4P1TML7xBWhEQBvJOeM1da7LgAZu-9nyy65028FJqo9V5q5SagZBrsFJTVdvIqpGZuERqG-PjOnMr4sKIRcnX35YJNLwAUtNiyRjzaCIHvpq5xKf_zH_UdFbvR7IU02PiZ9ujxnOxyPkYD1ZUcgnAvI9-2stOo_oigoRHooDrMX_x3hGSoy8gFdLyVlt5QTPFJ4es9H4G3nd_S-I42Ny0J9cscsgGfGpaYHmF761z-Rll0pKEHb87xxMuB4-P3qKbpQkQAen5MGt-Q21PmUli3wZB7dSyfGIvHi9y_UsujqogsJvK7txIi9PaR5J8S-o3-dPFXAhuNMFNFeIOe8jQ3iw1ZznLMoX4ATuZi30jg79xdOfDjNoyEY0uJdz_5H3mioJCDDYmZ8XR7X-cB_aToIZ4f_WcJ1y5dWQ3izWCJakUf3FkxepXixIk0KJU3oyo5D5HNM-UkhbL7M"
	token, err := parseSAToken(saTokenString)
	if err != nil {
		t.Error("failed to parse", err)
	}

	t.Log(token.K8s)
}
