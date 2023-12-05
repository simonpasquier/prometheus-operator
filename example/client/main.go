package main

import (
	"context"
	"fmt"

	"github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// Run the program with the default group name:
// go run ./example/client/.
//
// Run the program with a custom group name:
// go run -ldflags="-s -X github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring.GroupName=monitoring.example.com" ./example/client/.
func main() {
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		panic(err)
	}

	cs, err := versioned.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}

	smons, err := cs.MonitoringV1().ServiceMonitors("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, smon := range smons.Items {
		fmt.Printf("%s: %s/%s\n", smon.GetObjectKind().GroupVersionKind(), smon.GetNamespace(), smon.GetName())
	}
}
