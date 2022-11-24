// Copyright 2018 The prometheus-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"fmt"
	"strings"

	"github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	Version = "v1"

	PrometheusesKind  = "Prometheus"
	PrometheusName    = "prometheuses"
	PrometheusKindKey = "prometheus"

	AlertmanagersKind   = "Alertmanager"
	AlertmanagerName    = "alertmanagers"
	AlertManagerKindKey = "alertmanager"

	ServiceMonitorsKind   = "ServiceMonitor"
	ServiceMonitorName    = "servicemonitors"
	ServiceMonitorKindKey = "servicemonitor"

	PodMonitorsKind   = "PodMonitor"
	PodMonitorName    = "podmonitors"
	PodMonitorKindKey = "podmonitor"

	PrometheusRuleKind    = "PrometheusRule"
	PrometheusRuleName    = "prometheusrules"
	PrometheusRuleKindKey = "prometheusrule"

	ProbesKind   = "Probe"
	ProbeName    = "probes"
	ProbeKindKey = "probe"
)

var resourceToKind = map[string]string{
	PrometheusName:     PrometheusesKind,
	AlertmanagerName:   AlertmanagersKind,
	ServiceMonitorName: ServiceMonitorsKind,
	PodMonitorName:     PodMonitorsKind,
	PrometheusRuleName: PrometheusRuleKind,
	ProbeName:          ProbesKind,
}

// CommonPrometheusFields are the options available to both the Prometheus server and agent.
// +k8s:deepcopy-gen=true
type CommonPrometheusFields struct {
	// PodMetadata configures labels and annotations which are propagated to the Prometheus pods.
	PodMetadata *EmbeddedObjectMetadata `json:"podMetadata,omitempty"`
	// ServiceMonitors to be selected for target discovery. An empty label
	// selector matches all objects. A null label selector matches no objects.
	//
	// *Deprecated:* if `spec.serviceMonitorSelector`,
	// `spec.podMonitorSelector` and `spec.probeSelector` are null, the
	// configuration is unmanaged. The Prometheus operator will ensure that the
	// Prometheus configuration's Secret exists but it is the responbility of
	// the user to provide the raw gzipped Prometheus configuration under the
	// `prometheus.yaml.gz` key. The recommended approach is to
	// use `spec.additionalScrapeConfigs` instead.
	ServiceMonitorSelector *metav1.LabelSelector `json:"serviceMonitorSelector,omitempty"`
	// Namespaces to match for ServicedMonitors discovery. An empty label selector
	// matches all namespaces. A null label selector matches the current
	// namespace only.
	ServiceMonitorNamespaceSelector *metav1.LabelSelector `json:"serviceMonitorNamespaceSelector,omitempty"`
	// *Experimental* PodMonitors to be selected for target discovery. An
	// empty label selector matches all objects. A null label selector matches
	// no objects.
	//
	// *Deprecated:* if `spec.serviceMonitorSelector`,
	// `spec.podMonitorSelector` and `spec.probeSelector` are null, the
	// configuration is unmanaged. The Prometheus operator will ensure that the
	// Prometheus configuration's Secret exists but it is the responbility of
	// the user to provide the raw gzipped Prometheus configuration under the
	// `prometheus.yaml.gz` key. The recommended approach is to
	// use `spec.additionalScrapeConfigs` instead.
	PodMonitorSelector *metav1.LabelSelector `json:"podMonitorSelector,omitempty"`
	// Namespaces to match for PodMonitors discovery. An empty label selector
	// matches all namespaces. A null label selector matches the current
	// namespace only.
	PodMonitorNamespaceSelector *metav1.LabelSelector `json:"podMonitorNamespaceSelector,omitempty"`
	// *Experimental* Probes to be selected for target discovery. An empty
	// label selector matches all objects. A null label selector matches no
	// objects.
	//
	// *Deprecated:* if `spec.serviceMonitorSelector`,
	// `spec.podMonitorSelector` and `spec.probeSelector` are null, the
	// configuration is unmanaged. The Prometheus operator will ensure that the
	// Prometheus configuration's Secret exists but it is the responbility of
	// the user to provide the raw gzipped Prometheus configuration under the
	// `prometheus.yaml.gz` key. The recommended approach is to
	// use `spec.additionalScrapeConfigs` instead.
	ProbeSelector *metav1.LabelSelector `json:"probeSelector,omitempty"`
	// Namespaces to match for Probes discovery. An empty label selector
	// matches all namespaces. A null label selector matches the current
	// namespace only.
	ProbeNamespaceSelector *metav1.LabelSelector `json:"probeNamespaceSelector,omitempty"`
	// Version of Prometheus being deployed. If not specified, the operator
	// assumes the latest upstream version of Prometheus available at the time
	// when the version of the operator was released.
	Version string `json:"version,omitempty"`
	// When a Prometheus deployment is paused, no actions except for deletion
	// will be performed on the underlying objects.
	Paused bool `json:"paused,omitempty"`
	// Container image name for Prometheus. If specified, it takes precedence
	// over the `spec.baseImage`, `spec.tag` and `spec.sha` fields.
	// Specifying `spec.version` is still necessary to ensure the Prometheus
	// Operator knows which version of Prometheus is being configured.
	// If neither `spec.image` nor `spec.baseImage` are
	// defined, the operator will use the latest upstream version of
	// Prometheus available at the time when the operator was released.
	Image *string `json:"image,omitempty"`
	// An optional list of references to Secrets in the same namespace
	// to use for pulling images from registries.
	// see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Number of replicas of each shard to deploy for a Prometheus deployment.
	// `spec.replicas` multiplied by `spec.shards` is the total number of Pods
	// created.
	//
	// Default: 1
	Replicas *int32 `json:"replicas,omitempty"`
	// EXPERIMENTAL: Number of shards to distribute targets onto. `spec.replicas`
	// multiplied by `spec.shards` is the total number of Pods created.
	//
	// Note that scaling down shards will not reshard data onto remaining
	// instances, it must be manually moved. Increasing shards will not reshard
	// data either but it will continue to be available from the same
	// instances. To query globally use Thanos sidecar and Thanos querier or
	// remote write data to a central location.
	//
	// Sharding is done on the content of the `__address__` target meta-label
	// for PodMonitors and ServiceMonitors and `__param_target__` for Probes.
	//
	// Default: 1
	Shards *int32 `json:"shards,omitempty"`
	// Name of Prometheus external label used to denote replica name.
	// The External label will _not_ be added when the field is set to the
	// empty string (`""`).
	// Default: "prometheus_replica"
	ReplicaExternalLabelName *string `json:"replicaExternalLabelName,omitempty"`
	// Name of Prometheus external label used to denote Prometheus instance
	// name.
	// The External label will _not_ be added when the field is set to the
	// empty string (`""`).
	// Default: "prometheus"
	PrometheusExternalLabelName *string `json:"prometheusExternalLabelName,omitempty"`
	// Log level for Prometheus and the config-reloader sidecar.
	//+kubebuilder:validation:Enum="";debug;info;warn;error
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for Prometheus and the config-reloader sidecar.
	//+kubebuilder:validation:Enum="";logfmt;json
	LogFormat string `json:"logFormat,omitempty"`
	// Interval between consecutive scrapes.
	// Default: "30s"
	// +kubebuilder:default:="30s"
	ScrapeInterval Duration `json:"scrapeInterval,omitempty"`
	// Number of seconds to wait until a scrape request times out.
	ScrapeTimeout Duration `json:"scrapeTimeout,omitempty"`
	// The labels to add to any time series or alerts when communicating with
	// external systems (federation, remote storage, Alertmanager).
	// Labels defined by `spec.replicaExternalLabelName` and
	// `spec.prometheusExternalLabelName` take precedence over this list.
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
	// Enable Prometheus to be used as a receiver for the Prometheus remote
	// write protocol.
	// WARNING: This is not considered an efficient way of ingesting samples.
	// Use it with caution for specific low-volume use cases.
	// It is not suitable for replacing the ingestion via scraping and turning
	// Prometheus into a push-based metrics collection system.
	// For more information see https://prometheus.io/docs/prometheus/latest/querying/api/#remote-write-receiver
	// Only valid in Prometheus versions 2.33.0 and newer.
	EnableRemoteWriteReceiver bool `json:"enableRemoteWriteReceiver,omitempty"`
	// Enable access to Prometheus feature flags. By default, no features are enabled.
	// Enabling features which are disabled by default is entirely outside the
	// scope of what the maintainers will support and by doing so, you accept
	// that this behaviour may break at any time without notice.
	// For more information see https://prometheus.io/docs/prometheus/latest/feature_flags/
	EnableFeatures []string `json:"enableFeatures,omitempty"`
	// The external URL under which the Prometheus service is externally
	// available. This is necessary to generate correct URLs (for instance if
	// Prometheus is accessible behind an Ingress resource).
	ExternalURL string `json:"externalUrl,omitempty"`
	// The route prefix Prometheus registers HTTP handlers for. This is useful,
	// if using `spec.externalURL` and a proxy is rewriting HTTP routes of a
	// request, and the actual ExternalURL is still true, but the server serves
	// requests under a different route prefix. For example for use with
	// `kubectl proxy`.
	RoutePrefix string `json:"routePrefix,omitempty"`
	// Storage defines the storage used by Prometheus.
	Storage *StorageSpec `json:"storage,omitempty"`
	// Volumes allows the configuration of additional volumes on the output
	// StatefulSet definition. Volumes specified will be appended to other
	// volumes that are generated as a result of StorageSpec objects.
	Volumes []v1.Volume `json:"volumes,omitempty"`
	// VolumeMounts allows the configuration of additional VolumeMounts for the
	// Prometheus.
	// VolumeMounts specified will be appended to other VolumeMounts in the
	// 'prometheus' container, that are generated as a result of StorageSpec
	// objects.
	VolumeMounts []v1.VolumeMount `json:"volumeMounts,omitempty"`
	// Defines the configuration of the Prometheus web server.
	Web *PrometheusWebSpec `json:"web,omitempty"`
	// Define the resources requests and limits of the 'prometheus' container.
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
	// Define on which Nodes the Pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// ServiceAccountName is the name of the ServiceAccount to use to run the
	// Prometheus Pods.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Secrets is a list of Secrets in the same namespace as the Prometheus
	// object, which shall be mounted into the Prometheus Pods.
	// Each Secret is added to the StatefulSet definition as a volume named `secret-<secret-name>`.
	// The Secrets are mounted into /etc/prometheus/secrets/<secret-name> in the 'prometheus' container.
	Secrets []string `json:"secrets,omitempty"`
	// ConfigMaps is a list of ConfigMaps in the same namespace as the Prometheus
	// object, which shall be mounted into the Prometheus Pods.
	// Each ConfigMap is added to the StatefulSet definition as a volume named `configmap-<configmap-name>`.
	// The ConfigMaps are mounted into /etc/prometheus/configmaps/<configmap-name> in the 'prometheus' container.
	ConfigMaps []string `json:"configMaps,omitempty"`
	// If specified, the Pods' affinity scheduling rules.
	Affinity *v1.Affinity `json:"affinity,omitempty"`
	// If specified, the Pods' tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// If specified, the Pods' topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// remoteWrite is the list of remote-write configurations.
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// SecurityContext holds pod-level security attributes and common container settings.
	// This defaults to the default PodSecurityContext.
	SecurityContext *v1.PodSecurityContext `json:"securityContext,omitempty"`
	// When true, the Prometheus server listens on the loopback address
	// instead of the Pod IP's address.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// Containers allows injecting additional containers or modifying operator
	// generated containers. This can be used to allow adding an authentication
	// proxy to the Pods or to change the behavior of an operator generated
	// container. Containers described here modify an operator generated
	// container if they share the same name and modifications are done via a
	// strategic merge patch.
	// The names of containers managed by the operator are:
	//	`prometheus`, `config-reloader`, and `thanos-sidecar`.
	//
	// Overriding containers is entirely outside the scope of what the
	// maintainers will support and by doing so, you accept that this behaviour
	// may break at any time without notice.
	Containers []v1.Container `json:"containers,omitempty"`
	// InitContainers allows injecting initContainers to the Pod definition. Those
	// can be used to e.g.  fetch secrets for injection into the Prometheus
	// configuration from external sources. Any errors during the execution of
	// an initContainer will lead to a restart of the Pod. More info:
	// https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
	// InitContainers described here modify an operator generated init
	// containers if they share the same name and modifications are done via a
	// strategic merge patch.
	// The names of init container name managed by the operator are:
	// `init-config-reloader`.
	//
	// Overriding init containers is entirely outside the scope of what the
	// maintainers will support and by doing so, you accept that this behaviour
	// may break at any time without notice.
	InitContainers []v1.Container `json:"initContainers,omitempty"`
	// AdditionalScrapeConfigs allows specifying a key of a Secret containing
	// additional Prometheus scrape configurations. Scrape configurations
	// specified are appended to the configurations generated by the Prometheus
	// Operator. Job configurations specified must have the form as specified
	// in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config.
	// As scrape configs are appended, the user is responsible to make sure it
	// is valid. Note that using this feature may expose the possibility to
	// break upgrades of Prometheus. It is advised to review Prometheus release
	// notes to ensure that no incompatible scrape configs are going to break
	// Prometheus after the upgrade.
	AdditionalScrapeConfigs *v1.SecretKeySelector `json:"additionalScrapeConfigs,omitempty"`
	// APIServerConfig allows specifying a host and auth methods to access apiserver.
	// If null, Prometheus is assumed to run inside of the cluster: it will
	// discover the API servers automatically and use the Pod's CA certificate
	// and bearer token file at /var/run/secrets/kubernetes.io/serviceaccount/.
	APIServerConfig *APIServerConfig `json:"apiserverConfig,omitempty"`
	// Priority class assigned to the Pods.
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// Port name used for the pods and governing service.
	// Default: "web"
	PortName string `json:"portName,omitempty"`
	// When true, ServiceMonitor, PodMonitor and Probe object are forbidden to
	// reference arbitrary files on the file system of the 'prometheus'
	// container.
	// When a ServiceMonitor's endpoint specifies a `bearerTokenFile` value
	// (e.g.  '/var/run/secrets/kubernetes.io/serviceaccount/token'), a
	// malicious target can get access to the Prometheus service account's
	// token in the Prometheus' scrape request. Setting
	// `spec.arbitraryFSAccessThroughSM` to 'true' would prevent the attack.
	// Users should instead provide the credentials using the
	// `spec.bearerTokenSecret` field.
	ArbitraryFSAccessThroughSMs ArbitraryFSAccessThroughSMsConfig `json:"arbitraryFSAccessThroughSMs,omitempty"`
	// When true, Prometheus resolves label conflicts by renaming the labels in
	// the scraped data to "exported_<label value>" for all targets created
	// from service and pod monitors.
	// Otherwise the HonorLabels field of the service or pod monitor applies.
	OverrideHonorLabels bool `json:"overrideHonorLabels,omitempty"`
	// When true, Prometheus ignores the timestamps for all the targets created
	// from service and pod monitors.
	// Otherwise the HonorTimestamps field of the service or pod monitor applies.
	OverrideHonorTimestamps bool `json:"overrideHonorTimestamps,omitempty"`
	// When true, `spec.namespaceSelector` from all PodMonitor, ServiceMonitor
	// and Probe objects will be ignored. They will only discover targets
	// within the namespace of the PodMonitor, ServiceMonitor and Probe
	// object.
	// Default: false
	IgnoreNamespaceSelectors bool `json:"ignoreNamespaceSelectors,omitempty"`
	// When not empty, a label will be added to
	//
	// 1. All metrics scraped from `ServiceMonitor`, `PodMonitor` and `Probe` objects.
	// 2. All metrics generated from recording rules defined in `PrometheusRule` objects.
	// 3. All alerts generated from alerting rules defined in `PrometheusRule` objects.
	// 4. All vector selectors of PromQL expressions defined in `PrometheusRule` objects.
	//
	// The label will not added for objects referenced in `spec.excludedFromEnforcement`.
	//
	// The label's name is this field's value.
	// The label's value is the namespace of the `ServiceMonitor`,
	// `PodMonitor`, `Probe` or `PrometheusRule` object.
	EnforcedNamespaceLabel string `json:"enforcedNamespaceLabel,omitempty"`
	// When not null, enforcedSampleLimit defines a global limit on the number
	// of scraped samples that will be accepted. This overrides any
	// `spec.sampleLimit` set by ServiceMonitor, PodMonitor, Probe objects
	// unless `spec.sampleLimit` is greater than zero and less than than
	// `spec.enforcedSampleLimit`.
	// It is meant to be used by admins to enforce the SampleLimit to keep
	// overall number of samples/series under the desired limit.
	EnforcedSampleLimit *uint64 `json:"enforcedSampleLimit,omitempty"`
	// When not null, enforcedTargetLimit defines a global limit on the number
	// of scraped targets. The value overrides any `spec.targetLimit` set by
	// ServiceMonitor, PodMonitor, Probe objects unless `spec.targetLimit` is
	// greater than zero and less than `spec.enforcedTargetLimit`.
	// It is meant to be used by admins to enforce the TargetLimit to keep the
	// overall number of targets under the desired limit.
	EnforcedTargetLimit *uint64 `json:"enforcedTargetLimit,omitempty"`
	// When not null, enforcedLabelLimit defines a global limit on the number
	// of labels per sample. The value overrides any `spec.labelLimit` set by
	// ServiceMonitor, PodMonitor, Probe objects unless `spec.labelLimit` is
	// greater than zero and less than `spec.enforcedLabelLimit`.
	// Only valid in Prometheus versions 2.27.0 and newer.
	EnforcedLabelLimit *uint64 `json:"enforcedLabelLimit,omitempty"`
	// When not null, enforcedLabelNameLengthLimit defines a global limit on the length
	// of labels name per sample. The value overrides any `spec.labelNameLengthLimit` set by
	// ServiceMonitor, PodMonitor, Probe objects unless `spec.labelNameLengthLimit` is
	// greater than zero and less than `spec.enforcedLabelNameLengthLimit`.
	// Only valid in Prometheus versions 2.27.0 and newer.
	EnforcedLabelNameLengthLimit *uint64 `json:"enforcedLabelNameLengthLimit,omitempty"`
	// When not null, enforcedLabelValueLengthLimit defines a global limit on the length
	// of labels value per sample. The value overrides any `spec.labelValueLengthLimit` set by
	// ServiceMonitor, PodMonitor, Probe objects unless `spec.labelValueLengthLimit` is
	// greater than zero and less than `spec.enforcedLabelValueLengthLimit`.
	// Only valid in Prometheus versions 2.27.0 and newer.
	EnforcedLabelValueLengthLimit *uint64 `json:"enforcedLabelValueLengthLimit,omitempty"`
	// When not null, enforcedBodySizeLimit defines a global limit on the size
	// of uncompressed response body that will be accepted by Prometheus.
	// Targets responding with a body larger than this many bytes will cause
	// the scrape to fail.
	// Only valid in Prometheus versions 2.28.0 and newer.
	EnforcedBodySizeLimit ByteSize `json:"enforcedBodySizeLimit,omitempty"`
	// Minimum number of seconds for which a newly created pod should be ready
	// without any of its container crashing for it to be considered available.
	// Defaults to 0 (pod will be considered available as soon as it is ready)
	// This is an alpha field and requires enabling StatefulSetMinReadySeconds feature gate.
	// +optional
	MinReadySeconds *uint32 `json:"minReadySeconds,omitempty"`
	// Optional list of hosts and IPs that will be injected into the pod's
	// hosts file if specified.
	// +listType=map
	// +listMapKey=ip
	HostAliases []HostAlias `json:"hostAliases,omitempty"`
	// AdditionalArgs allows setting additional arguments for the 'prometheus' container.
	// It is intended for e.g. activating hidden flags which are not supported by
	// the dedicated configuration options yet. The arguments are passed as-is to the
	// Prometheus container which may cause issues if they are invalid or not supported
	// by the given Prometheus version.
	// In case of an argument conflict (e.g. an argument which is already set by the
	// operator itself) or when providing an invalid argument the reconciliation will
	// fail and an error will be logged.
	AdditionalArgs []Argument `json:"additionalArgs,omitempty"`
	// Enable compression of the write-ahead log using Snappy.
	// This flag is only available in versions of Prometheus >= 2.11.0.
	WALCompression *bool `json:"walCompression,omitempty"`
	// List of references to PodMonitor, ServiceMonitor, Probe and PrometheusRule objects
	// to be excluded from enforcing a namespace label of origin.
	// It is only applicable if `spec.enforcedNamespaceLabel` set to true.
	ExcludedFromEnforcement []ObjectReference `json:"excludedFromEnforcement,omitempty"`
	// Use the host's network namespace if true.
	// Make sure to understand the security implications if you want to enable it (https://kubernetes.io/docs/concepts/configuration/overview/).
	// When hostNetwork is enabled, this will set the DNS policy to `ClusterFirstWithHostNet` automatically.
	HostNetwork bool `json:"hostNetwork,omitempty"`
}

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="prom"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version",description="The version of Prometheus"
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=".spec.replicas",description="The number of desired replicas"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.availableReplicas",description="The number of ready replicas"
// +kubebuilder:printcolumn:name="Reconciled",type="string",JSONPath=".status.conditions[?(@.type == 'Reconciled')].status"
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type == 'Available')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Paused",type="boolean",JSONPath=".status.paused",description="Whether the resource reconciliation is paused or not",priority=1
// +kubebuilder:subresource:status

// Prometheus defines a Prometheus deployment.
type Prometheus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the Prometheus cluster. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec PrometheusSpec `json:"spec"`
	// Most recent observed status of the Prometheus cluster. Read-only.
	// More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status PrometheusStatus `json:"status,omitempty"`
}

// PrometheusList is a list of Prometheuses.
// +k8s:openapi-gen=true
type PrometheusList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of Prometheuses
	Items []*Prometheus `json:"items"`
}

// ByteSize is a valid memory size type based on powers-of-2, so 1KB is 1024B.
// Supported units: B, KB, KiB, MB, MiB, GB, GiB, TB, TiB, PB, PiB, EB, EiB Ex: `512MB`.
// +kubebuilder:validation:Pattern:="(^0|([0-9]*[.])?[0-9]+((K|M|G|T|E|P)i?)?B)$"
type ByteSize string

// Duration is a valid time duration that can be parsed by Prometheus model.ParseDuration() function.
// Supported units: y, w, d, h, m, s, ms
// Examples: `30s`, `1m`, `1h20m15s`, `15d`
// +kubebuilder:validation:Pattern:="^(0|(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?)$"
type Duration string

// GoDuration is a valid time duration that can be parsed by Go's time.ParseDuration() function.
// Supported units: h, m, s, ms
// Examples: `45ms`, `30s`, `1m`, `1h20m15s`
// +kubebuilder:validation:Pattern:="^(0|(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?)$"
type GoDuration string

// HostAlias holds the mapping between IP and hostnames that will be injected as an entry in the
// pod's hosts file.
type HostAlias struct {
	// IP address of the host file entry.
	// +kubebuilder:validation:Required
	IP string `json:"ip"`
	// Hostnames for the above IP address.
	// +kubebuilder:validation:Required
	Hostnames []string `json:"hostnames"`
}

// PrometheusSpec is a specification of the desired behavior of the Prometheus cluster. More info:
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
// +k8s:openapi-gen=true
type PrometheusSpec struct {
	CommonPrometheusFields `json:",inline"`
	// *Deprecated: use 'spec.image' instead.*
	BaseImage string `json:"baseImage,omitempty"`
	// *Deprecated: use 'spec.image' instead. The image's tag can be specified
	// as part of the image name.*
	Tag string `json:"tag,omitempty"`
	// *Deprecated: use 'image' instead. The image's digest can be specified as
	// part of the image name.*
	SHA string `json:"sha,omitempty"`
	// Time duration Prometheus shall retain data for. Default is '24h' if
	// retentionSize is not set.
	// The value must match the regular expression `[0-9]+(ms|s|m|h|d|w|y)`
	// (milliseconds seconds minutes hours days weeks years).
	Retention Duration `json:"retention,omitempty"`
	// Maximum amount of disk space used by the Prometheus data.
	RetentionSize ByteSize `json:"retentionSize,omitempty"`
	// When true, the Prometheus compaction is disabled.
	DisableCompaction bool `json:"disableCompaction,omitempty"`
	// Defines the configuration of the Prometheus rules' engine.
	Rules Rules `json:"rules,omitempty"`
	// Defines the list of PrometheusRule objects to which the namespace label
	// enforcement doesn't apply.
	// This is only relevant when `spec.enforcedNamespaceLabel` is set to true.
	// *Deprecated: use `spec.excludedFromEnforcement` instead.*
	PrometheusRulesExcludedFromEnforce []PrometheusRuleExcludeConfig `json:"prometheusRulesExcludedFromEnforce,omitempty"`
	// QuerySpec defines the configuration of the Promethus query service.
	Query *QuerySpec `json:"query,omitempty"`
	// PrometheusRule objects to be selected for rule evaluation. An empty
	// label selector matches all objects. A null label selector matches no
	// objects.
	RuleSelector *metav1.LabelSelector `json:"ruleSelector,omitempty"`
	// Namespaces to match for PrometheusRule discovery. An empty label selector
	// matches all namespaces. A null label selector matches the current
	// namespace only.
	RuleNamespaceSelector *metav1.LabelSelector `json:"ruleNamespaceSelector,omitempty"`
	// Defines the settings related to Alertmanager.
	Alerting *AlertingSpec `json:"alerting,omitempty"`
	// Defines the list of remote read configurations.
	RemoteRead []RemoteReadSpec `json:"remoteRead,omitempty"`
	// AdditionalAlertRelabelConfigs allows specifying a key of a Secret containing
	// additional Prometheus alert relabel configurations. Alert relabel configurations
	// specified are appended to the configurations generated by the Prometheus
	// Operator. Alert relabel configurations must have the form as specified
	// in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alert_relabel_configs.
	// As alert relabel configs are appended, the user is responsible to make sure it
	// is valid. Note that using this feature may expose the possibility to
	// break upgrades of Prometheus. It is advised to review Prometheus release
	// notes to ensure that no incompatible alert relabel configs are going to break
	// Prometheus after the upgrade.
	AdditionalAlertRelabelConfigs *v1.SecretKeySelector `json:"additionalAlertRelabelConfigs,omitempty"`
	// AdditionalAlertManagerConfigs allows specifying a key of a Secret containing
	// additional Prometheus AlertManager configurations. AlertManager configurations
	// specified are appended to the configurations generated by the Prometheus
	// Operator. Alertmanager configurations must have the form as specified
	// in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alertmanager_config.
	// As AlertManager configs are appended, the user is responsible to make sure it
	// is valid. Note that using this feature may expose the possibility to
	// break upgrades of Prometheus. It is advised to review Prometheus release
	// notes to ensure that no incompatible AlertManager configs are going to break
	// Prometheus after the upgrade.
	AdditionalAlertManagerConfigs *v1.SecretKeySelector `json:"additionalAlertManagerConfigs,omitempty"`
	// Defines the configuration of the optional Thanos sidecar.
	//
	// This is experimental and may change significantly without backward
	// compatibility in any release.
	Thanos *ThanosSpec `json:"thanos,omitempty"`
	// queryLogFile specifies where the file to which PromQL queries are logged.
	//
	// If the filename has an empty path, e.g. 'query.log', The Prometheus Pods
	// will mount the file into an emptyDir volume at `/var/log/prometheus`.
	// If a full path is provided, e.g. '/var/log/prometheus/query.log', you
	// must mount a volume in the specified directory and it must be writable.
	// This is because the prometheus container runs with a read-only root
	// filesystem for security reasons.
	// Alternatively, the location can be set to a standard I/O stream, e.g.
	// `/dev/stdout`, to log query information to the default Prometheus log
	// stream.
	// This is only available in versions of Prometheus >= 2.16.0.
	// For more details, see the Prometheus docs (https://prometheus.io/docs/guides/query-log/)
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// AllowOverlappingBlocks enables vertical compaction and vertical query
	// merge in Prometheus.
	// *Deprecated: this field will be removed in the future because
	// overalapping blocks are always allowed for Prometheus >= v2.39.0.*
	AllowOverlappingBlocks bool `json:"allowOverlappingBlocks,omitempty"`
	// Exemplars related settings that are runtime reloadable.
	// It requires to enable the `exemplar-storage` feature flag to be effective.
	Exemplars *Exemplars `json:"exemplars,omitempty"`
	// Interval between rule evaluations.
	// Default: '30s'
	// +kubebuilder:default:="30s"
	EvaluationInterval Duration `json:"evaluationInterval,omitempty"`
	// Enables access to the Prometheus web admin API.
	// WARNING: Enabling the admin APIs enables mutating endpoints, to delete data,
	// shutdown Prometheus, and more. Enabling this should be done with care and the
	// user is advised to add additional authentication authorization via a proxy to
	// ensure only clients authorized to perform these actions can do so.
	// For more information see https://prometheus.io/docs/prometheus/latest/querying/api/#tsdb-admin-apis
	EnableAdminAPI bool `json:"enableAdminAPI,omitempty"`
	// Defines the runtime reloadable configuration of the timeseries database
	// (TSDB).
	TSDB TSDBSpec `json:"tsdb,omitempty"`
}

type TSDBSpec struct {
	// Configures how old an out-of-order/out-of-bounds sample can be w.r.t.
	// the TSDB max time.
	// An out-of-order/out-of-bounds sample is ingested into the TSDB as long as
	// the timestamp of the sample is >= (TSDB.MaxTime - outOfOrderTimeWindow).
	// Out of order ingestion is an experimental feature and requires
	// Prometheus >= v2.39.0.
	OutOfOrderTimeWindow Duration `json:"outOfOrderTimeWindow,omitempty"`
}

type Exemplars struct {
	// Maximum number of exemplars stored in memory for all series.
	// If not set, Prometheus uses its default value.
	// A value of zero or less than zero disables the storage.
	MaxSize *int64 `json:"maxSize,omitempty"`
}

// PrometheusRuleExcludeConfig enables users to configure excluded
// PrometheusRule names and their namespaces to be ignored while enforcing
// namespace label for alerts and metrics.
type PrometheusRuleExcludeConfig struct {
	// Namespace of the excluded PrometheusRule object.
	RuleNamespace string `json:"ruleNamespace"`
	// Name of the excluded PrometheusRule object.
	RuleName string `json:"ruleName"`
}

// ObjectReference references a PodMonitor, ServiceMonitor, Probe or PrometheusRule object.
type ObjectReference struct {
	// Group of the referent. When not specified, it defaults to `monitoring.coreos.com`
	// +optional
	// +kubebuilder:default:="monitoring.coreos.com"
	// +kubebuilder:validation:Enum=monitoring.coreos.com
	Group string `json:"group"`
	// Resource of the referent.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=prometheusrules;servicemonitors;podmonitors;probes
	Resource string `json:"resource"`
	// Namespace of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// Name of the referent. When not set, all resources in the namespace are matched.
	// +optional
	Name string `json:"name,omitempty"`
}

func (obj *ObjectReference) GroupResource() schema.GroupResource {
	return schema.GroupResource{
		Resource: obj.Resource,
		Group:    obj.getGroup(),
	}
}

func (obj *ObjectReference) GroupKind() schema.GroupKind {
	_, found := resourceToKind[obj.Resource]
	if !found {
		panic(fmt.Sprintf("failed to map resource %q to a kind", obj.Resource))
	}
	return schema.GroupKind{
		Kind:  resourceToKind[obj.Resource],
		Group: obj.getGroup(),
	}
}

// getGroup returns the group of the object.
// It is mostly needed for tests which don't create objects through the API and don't benefit from the default value.
func (obj *ObjectReference) getGroup() string {
	if obj.Group == "" {
		return monitoring.GroupName
	}
	return obj.Group
}

type ArbitraryFSAccessThroughSMsConfig struct {
	Deny bool `json:"deny,omitempty"`
}

// PrometheusStatus is the most recent observed status of the Prometheus cluster.
// More info:
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
// +k8s:openapi-gen=true
type PrometheusStatus struct {
	// Represents whether any actions on the underlying managed objects are
	// being performed. Only delete actions will be performed.
	Paused bool `json:"paused"`
	// Total number of non-terminated pods targeted by this Prometheus deployment
	// (their labels match the selector).
	Replicas int32 `json:"replicas"`
	// Total number of non-terminated pods targeted by this Prometheus deployment
	// that have the desired version spec.
	UpdatedReplicas int32 `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this Prometheus deployment.
	AvailableReplicas int32 `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this Prometheus deployment.
	UnavailableReplicas int32 `json:"unavailableReplicas"`
	// The current state of the Prometheus deployment.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []PrometheusCondition `json:"conditions,omitempty"`
	// The list has one entry per shard. Each entry provides a summary of the shard status.
	// +listType=map
	// +listMapKey=shardID
	// +optional
	ShardStatuses []ShardStatus `json:"shardStatuses,omitempty"`
}

// PrometheusCondition represents the state of the resources associated with the Prometheus resource.
// +k8s:deepcopy-gen=true
type PrometheusCondition struct {
	// Type of the condition being reported.
	// +required
	Type PrometheusConditionType `json:"type"`
	// status of the condition.
	// +required
	Status PrometheusConditionStatus `json:"status"`
	// lastTransitionTime is the time of the last update to the current status property.
	// +required
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`
	// Reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Human-readable message indicating details for the condition's last transition.
	// +optional
	Message string `json:"message,omitempty"`
	// ObservedGeneration represents the .metadata.generation that the condition was set based upon.
	// For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the instance.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

type PrometheusConditionType string

const (
	// Available indicates whether enough Prometheus pods are ready to provide
	// the service.
	// The possible status values for this condition type are:
	// - True: all pods are running and ready, the service is fully available.
	// - Degraded: some pods aren't ready, the service is partially available.
	// - False: no pods are running, the service is totally unavailable.
	// - Unknown: the operator couldn't determine the condition status.
	PrometheusAvailable PrometheusConditionType = "Available"
	// Reconciled indicates whether the operator has reconciled the state of
	// the underlying resources with the Prometheus object spec.
	// The possible status values for this condition type are:
	// - True: the reconciliation was successful.
	// - False: the reconciliation failed.
	// - Unknown: the operator couldn't determine the condition status.
	PrometheusReconciled PrometheusConditionType = "Reconciled"
)

type PrometheusConditionStatus string

const (
	PrometheusConditionTrue     PrometheusConditionStatus = "True"
	PrometheusConditionDegraded PrometheusConditionStatus = "Degraded"
	PrometheusConditionFalse    PrometheusConditionStatus = "False"
	PrometheusConditionUnknown  PrometheusConditionStatus = "Unknown"
)

type ShardStatus struct {
	// Identifier of the shard.
	// +required
	ShardID string `json:"shardID"`
	// Total number of pods targeted by this shard.
	Replicas int32 `json:"replicas"`
	// Total number of non-terminated pods targeted by this shard
	// that have the desired spec.
	UpdatedReplicas int32 `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this shard.
	AvailableReplicas int32 `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this shard.
	UnavailableReplicas int32 `json:"unavailableReplicas"`
}

// AlertingSpec defines parameters for alerting configuration of Prometheus servers.
// +k8s:openapi-gen=true
type AlertingSpec struct {
	// AlertmanagerEndpoints Prometheus should fire alerts against.
	Alertmanagers []AlertmanagerEndpoints `json:"alertmanagers"`
}

// StorageSpec defines the configured storage for a group Prometheus servers.
// If no storage option is specified, then by default an [EmptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) will be used.
// If multiple storage options are specified, priority will be given as follows:
// 1. emptyDir
// 2. ephemeral
// 3. volumeClaimTemplate
// +k8s:openapi-gen=true
type StorageSpec struct {
	// DisableMountSubPath allows to remove any subPath usage in volume mounts.
	// *Deprecated: subPath usage will be disabled by default in a future
	// release, this option will become unnecessary.*
	DisableMountSubPath bool `json:"disableMountSubPath,omitempty"`
	// EmptyDirVolumeSource to be used by the Prometheus StatefulSets. If specified, used in place of any volumeClaimTemplate. More
	// info: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
	EmptyDir *v1.EmptyDirVolumeSource `json:"emptyDir,omitempty"`
	// EphemeralVolumeSource to be used by the Prometheus StatefulSets.
	// This is a beta field in k8s 1.21, for lower versions, starting with k8s 1.19, it requires enabling the GenericEphemeralVolume feature gate.
	// More info: https://kubernetes.io/docs/concepts/storage/ephemeral-volumes/#generic-ephemeral-volumes
	Ephemeral *v1.EphemeralVolumeSource `json:"ephemeral,omitempty"`
	// Defines the PVC spec to be used by the Prometheus StatefulSets.
	VolumeClaimTemplate EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// EmbeddedPersistentVolumeClaim is an embedded version of k8s.io/api/core/v1.PersistentVolumeClaim.
// It contains TypeMeta and a reduced ObjectMeta.
type EmbeddedPersistentVolumeClaim struct {
	metav1.TypeMeta `json:",inline"`

	// EmbeddedMetadata contains metadata relevant to an EmbeddedResource.
	EmbeddedObjectMetadata `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Defines the desired characteristics of a volume requested by a pod author.
	// More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
	// +optional
	Spec v1.PersistentVolumeClaimSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`

	// Status represents the current information/status of a persistent volume claim.
	// Read-only.
	// *Deprecated: this field is never set.*
	// +optional
	Status v1.PersistentVolumeClaimStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// EmbeddedObjectMetadata contains a subset of the fields included in k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta
// Only fields which are relevant to embedded resources are included.
type EmbeddedObjectMetadata struct {
	// Name must be unique within a namespace. Is required when creating resources, although
	// some resources may allow a client to request the generation of an appropriate name
	// automatically. Name is primarily intended for creation idempotence and configuration
	// definition.
	// Cannot be updated.
	// More info: http://kubernetes.io/docs/user-guide/identifiers#names
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`

	// Map of string keys and values that can be used to organize and categorize
	// (scope and select) objects. May match selectors of replication controllers
	// and services.
	// More info: http://kubernetes.io/docs/user-guide/labels
	// +optional
	Labels map[string]string `json:"labels,omitempty" protobuf:"bytes,11,rep,name=labels"`

	// Annotations is an unstructured key value map stored with a resource that may be
	// set by external tools to store and retrieve arbitrary metadata. They are not
	// queryable and should be preserved when modifying objects.
	// More info: http://kubernetes.io/docs/user-guide/annotations
	// +optional
	Annotations map[string]string `json:"annotations,omitempty" protobuf:"bytes,12,rep,name=annotations"`
}

// QuerySpec defines the query command line flags when starting Prometheus.
// +k8s:openapi-gen=true
type QuerySpec struct {
	// The delta difference allowed for retrieving metrics during expression evaluations.
	// +optional
	LookbackDelta *string `json:"lookbackDelta,omitempty"`
	// Number of concurrent queries that can be run at once.
	// +optional
	MaxConcurrency *int32 `json:"maxConcurrency,omitempty"`
	// Maximum number of samples a single query can load into memory. Note that
	// queries will fail if they would load more samples than this into memory,
	// so this also limits the number of samples a query can return.
	// +optional
	MaxSamples *int32 `json:"maxSamples,omitempty"`
	// Maximum time a query may take before being aborted.
	// +optional
	Timeout *Duration `json:"timeout,omitempty"`
}

// PrometheusWebSpec defines the configuration of the Prometheus web server.
// +k8s:openapi-gen=true
type PrometheusWebSpec struct {
	WebConfigFileFields `json:",inline"`
	// The Prometheus web page title.
	// +optional
	PageTitle *string `json:"pageTitle,omitempty"`
}

// AlertmanagerWebSpec defines the configuration of the Alertmanager web server.
// +k8s:openapi-gen=true
type AlertmanagerWebSpec struct {
	WebConfigFileFields `json:",inline"`
}

// WebConfigFileFields defines the HTTP and TLS settings of the web server.
// +k8s:deepcopy-gen=true
type WebConfigFileFields struct {
	// Defines the TLS parameters for HTTPS.
	TLSConfig *WebTLSConfig `json:"tlsConfig,omitempty"`
	// Defines HTTP parameters for the web server.
	HTTPConfig *WebHTTPConfig `json:"httpConfig,omitempty"`
}

// WebHTTPConfig defines HTTP parameters for web server.
// +k8s:openapi-gen=true
type WebHTTPConfig struct {
	// Enable HTTP/2 support. Note that HTTP/2 is only supported with TLS.
	// When TLSConfig is not configured, HTTP/2 will be disabled.
	// Whenever the value of the field changes, a rolling update will be triggered.
	HTTP2 *bool `json:"http2,omitempty"`
	// List of headers that can be added to HTTP responses.
	Headers *WebHTTPHeaders `json:"headers,omitempty"`
}

// WebHTTPHeaders defines the list of headers that can be added to HTTP responses.
// +k8s:openapi-gen=true
type WebHTTPHeaders struct {
	// Set the Content-Security-Policy header to HTTP responses.
	// Unset if blank.
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty"`
	// Set the X-Frame-Options header to HTTP responses.
	// Unset if blank. Accepted values are deny and sameorigin.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
	//+kubebuilder:validation:Enum="";Deny;SameOrigin
	XFrameOptions string `json:"xFrameOptions,omitempty"`
	// Set the X-Content-Type-Options header to HTTP responses.
	// Unset if blank. Accepted value is nosniff.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
	//+kubebuilder:validation:Enum="";NoSniff
	XContentTypeOptions string `json:"xContentTypeOptions,omitempty"`
	// Set the X-XSS-Protection header to all responses.
	// Unset if blank.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
	XXSSProtection string `json:"xXSSProtection,omitempty"`
	// Set the Strict-Transport-Security header to HTTP responses.
	// Unset if blank.
	// Please make sure that you use this with care as this header might force
	// browsers to load Prometheus and the other applications hosted on the same
	// domain and subdomains over HTTPS.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
	StrictTransportSecurity string `json:"strictTransportSecurity,omitempty"`
}

// WebTLSConfig defines the TLS parameters for HTTPS.
// +k8s:openapi-gen=true
type WebTLSConfig struct {
	// Secret containing the TLS key for the server.
	KeySecret v1.SecretKeySelector `json:"keySecret"`
	// Contains the TLS certificate for the server.
	Cert SecretOrConfigMap `json:"cert"`
	// Server policy for client authentication. Maps to ClientAuth Policies.
	// For more detail on clientAuth options:
	// https://golang.org/pkg/crypto/tls/#ClientAuthType
	ClientAuthType string `json:"clientAuthType,omitempty"`
	// Contains the CA certificate for client certificate authentication to the server.
	ClientCA SecretOrConfigMap `json:"client_ca,omitempty"`
	// Minimum TLS version that is acceptable. Defaults to TLS12.
	MinVersion string `json:"minVersion,omitempty"`
	// Maximum TLS version that is acceptable. Defaults to TLS13.
	MaxVersion string `json:"maxVersion,omitempty"`
	// List of supported cipher suites for TLS versions up to TLS 1.2. If empty,
	// Go default cipher suites are used. Available cipher suites are documented
	// in the go documentation: https://golang.org/pkg/crypto/tls/#pkg-constants
	CipherSuites []string `json:"cipherSuites,omitempty"`
	// Controls whether the server selects the
	// client's most preferred cipher suite, or the server's most preferred
	// cipher suite. If true then the server's preference, as expressed in
	// the order of elements in cipherSuites, is used.
	PreferServerCipherSuites *bool `json:"preferServerCipherSuites,omitempty"`
	// Elliptic curves that will be used in an ECDHE handshake, in preference
	// order. Available curves are documented in the go documentation:
	// https://golang.org/pkg/crypto/tls/#CurveID
	CurvePreferences []string `json:"curvePreferences,omitempty"`
}

// WebTLSConfigError is returned by WebTLSConfig.Validate() on
// semantically invalid configurations.
// +k8s:openapi-gen=false
type WebTLSConfigError struct {
	err string
}

func (e *WebTLSConfigError) Error() string {
	return e.err
}

func (c *WebTLSConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.ClientCA != (SecretOrConfigMap{}) {
		if err := c.ClientCA.Validate(); err != nil {
			msg := fmt.Sprintf("invalid web tls config: %s", err.Error())
			return &WebTLSConfigError{msg}
		}
	}

	if c.Cert == (SecretOrConfigMap{}) {
		return &WebTLSConfigError{"invalid web tls config: cert must be defined"}
	} else if err := c.Cert.Validate(); err != nil {
		msg := fmt.Sprintf("invalid web tls config: %s", err.Error())
		return &WebTLSConfigError{msg}
	}

	if c.KeySecret == (v1.SecretKeySelector{}) {
		return &WebTLSConfigError{"invalid web tls config: key must be defined"}
	}

	return nil
}

// ThanosSpec defines the configuration of the Thanos sidecar.
// +k8s:openapi-gen=true
type ThanosSpec struct {
	// Container image name for Thanos. If specified, it takes precedence over
	// the `spec.thanos.baseImage`, `spec.thanos.tag` and `spec.thanos.sha`
	// fields.  Specifying `spec.thanos.version` is still necessary to ensure
	// the Prometheus Operator knows which version of Thanos is being
	// configured.
	// If neither `spec.thanos.image` nor `spec.thanos.baseImage` are defined,
	// the operator will use the latest upstream version of Thanos available at
	// the time when the operator was released.
	Image *string `json:"image,omitempty"`
	// Version of Thanos being deployed. If not specified, the operator assumes
	// the latest upstream release of Thanos available at the time when the
	// version of the operator was released.
	Version *string `json:"version,omitempty"`
	// *Deprecated: use 'image' instead. The image's tag can be specified as
	// part of the image name.*
	Tag *string `json:"tag,omitempty"`
	// *Deprecated: use 'image' instead.  The image digest can be specified
	// as part of the image name.*
	SHA *string `json:"sha,omitempty"`
	// *Deprecated: use 'image' instead.*
	BaseImage *string `json:"baseImage,omitempty"`
	// Resources defines the resource requirements for the Thanos sidecar.
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
	// ObjectStorageConfig configures the Thanos sidecar to upload TSDB blocks to object storage.
	// When used alongside with objectStorageConfigFile, objectStorageConfigFile takes precedence.
	ObjectStorageConfig *v1.SecretKeySelector `json:"objectStorageConfig,omitempty"`
	// ObjectStorageConfigFile specifies the path of the object storage configuration file.
	// When used alongside with objectStorageConfig, objectStorageConfigFile takes precedence.
	ObjectStorageConfigFile *string `json:"objectStorageConfigFile,omitempty"`
	// When true, the Thanos sidecar listens on the loopback address
	// instead of the Pod IP's address for HTTP and gRPC endpoints.
	//
	// It takes precedence over `grpcListenLocal` and `httpListenLocal`.
	//
	// *Deprecated: use `grpcListenLocal` and `httpListenLocal` instead.*
	ListenLocal bool `json:"listenLocal,omitempty"`
	// When true, the Thanos sidecar listens on the loopback interface instead
	// of the Pod IP's address for the gRPC endpoints.
	//
	// It has no effect if `listenLocal` is true.
	GRPCListenLocal bool `json:"grpcListenLocal,omitempty"`
	// When true, the Thanos sidecar listens on the loopback interface instead
	// of the Pod IP's address for the HTTP endpoints.
	//
	// It has no effect if `listenLocal` is true.
	HTTPListenLocal bool `json:"httpListenLocal,omitempty"`
	// TracingConfig configures tracing for the Thanos sidecar.
	// This is an experimental feature, it may change in any upcoming release
	// in a breaking way.
	TracingConfig *v1.SecretKeySelector `json:"tracingConfig,omitempty"`
	// TracingConfig specifies the path of the tracing configuration file.
	// When used alongside with TracingConfig, TracingConfigFile takes precedence.
	TracingConfigFile string `json:"tracingConfigFile,omitempty"`
	// GRPCServerTLSConfig configures the TLS parameters for the gRPC server
	// providing the StoreAPI.
	// Note: Currently only the `caFile`, `certFile`, and `keyFile` fields are supported.
	GRPCServerTLSConfig *TLSConfig `json:"grpcServerTlsConfig,omitempty"`
	// Log level for the Thanos sidecar.
	//+kubebuilder:validation:Enum="";debug;info;warn;error
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for the Thanos sidecar.
	//+kubebuilder:validation:Enum="";logfmt;json
	LogFormat string `json:"logFormat,omitempty"`
	// Defines the start of time range limit served by the Thanos sidecar's StoreAPI.
	// The field's value should be a constant time in RFC3339 format or a time
	// duration relative to current time, such as -1d or 2h45m. Valid duration
	// units are ms, s, m, h, d, w, y.
	MinTime string `json:"minTime,omitempty"`
	// ReadyTimeout is the maximum time that the Thanos sidecar will wait for
	// Prometheus to start.
	ReadyTimeout Duration `json:"readyTimeout,omitempty"`
	// VolumeMounts allows configuration of additional VolumeMounts for Thanos.
	// VolumeMounts specified will be appended to other VolumeMounts in the
	// 'thanos-sidecar' container.
	VolumeMounts []v1.VolumeMount `json:"volumeMounts,omitempty"`
	// AdditionalArgs allows setting additional arguments for the Thanos container.
	// The arguments are passed as-is to the Thanos container which may cause issues
	// if they are invalid or not supported the given Thanos version.
	// In case of an argument conflict (e.g. an argument which is already set by the
	// operator itself) or when providing an invalid argument the reconciliation will
	// fail and an error will be logged.
	AdditionalArgs []Argument `json:"additionalArgs,omitempty"`
}

// RemoteWriteSpec defines the configuration to write samples from Prometheus
// to a remote endpoint.
// +k8s:openapi-gen=true
type RemoteWriteSpec struct {
	// The URL of the endpoint to send samples to.
	URL string `json:"url"`
	// The name of the remote write queue, it must be unique if specified. The
	// name is used in metrics and logging in order to differentiate queues.
	// Only valid in Prometheus versions 2.15.0 and newer.
	Name string `json:"name,omitempty"`
	// Enables sending of exemplars over remote write. Note that
	// exemplar-storage itself must be enabled using the `spec.enableFeature`
	// option for exemplars to be scraped in the first place.
	// Only valid in Prometheus versions 2.27.0 and newer.
	SendExemplars *bool `json:"sendExemplars,omitempty"`
	// Timeout for requests to the remote write endpoint.
	RemoteTimeout Duration `json:"remoteTimeout,omitempty"`
	// Custom HTTP headers to be sent along with each remote write request.
	// Be aware that headers that are set by Prometheus itself can't be overwritten.
	// Only valid in Prometheus versions 2.25.0 and newer.
	Headers map[string]string `json:"headers,omitempty"`
	// The list of remote write relabel configurations.
	WriteRelabelConfigs []RelabelConfig `json:"writeRelabelConfigs,omitempty"`
	// OAuth2 for the URL. Only valid in Prometheus versions 2.27.0 and newer.
	//
	// Cannot be set at the same time as `sigv4`, `authorization`, or `basicAuth`.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// BasicAuth for the URL.
	//
	// Cannot be set at the same time as `sigv4`, `authorization`, or `oauth2`.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Bearer token for remote write.
	//
	// *Warning: this field shouldn't used because the token value appears in
	// clear-text. Prefer using `authorization`.*
	//
	// *Deprecated: this will be removed in a future release.*
	BearerToken string `json:"bearerToken,omitempty"`
	// File from which to read bearer token for remote write.
	//
	// *Deprecated: this will be removed in a future release. Prefer using `authorization`.*
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Authorization section for remote write.
	//
	// Cannot be set at the same time as `sigv4`, `basicAuth`, or `oauth2`.
	Authorization *Authorization `json:"authorization,omitempty"`
	// Sigv4 allows to configures AWS's Signature Verification 4.
	//
	// Cannot be set at the same time as `authorization`, `basicAuth`, or `oauth2`.
	Sigv4 *Sigv4 `json:"sigv4,omitempty"`
	// TLS Config to use for remote write.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Optional ProxyURL.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// QueueConfig allows tuning of the remote write queue parameters.
	QueueConfig *QueueConfig `json:"queueConfig,omitempty"`
	// MetadataConfig configures the sending of series metadata to the remote storage.
	MetadataConfig *MetadataConfig `json:"metadataConfig,omitempty"`
}

// QueueConfig allows the tuning of remote write's queue parameters.
// +k8s:openapi-gen=true
type QueueConfig struct {
	// Capacity is the number of samples to buffer per shard before we start
	// dropping them.
	Capacity int `json:"capacity,omitempty"`
	// MinShards is the minimum number of shards, i.e. amount of concurrency.
	MinShards int `json:"minShards,omitempty"`
	// MaxShards is the maximum number of shards, i.e. amount of concurrency.
	MaxShards int `json:"maxShards,omitempty"`
	// MaxSamplesPerSend is the maximum number of samples per send.
	MaxSamplesPerSend int `json:"maxSamplesPerSend,omitempty"`
	// BatchSendDeadline is the maximum time a sample will wait in buffer.
	BatchSendDeadline string `json:"batchSendDeadline,omitempty"`
	// MaxRetries is the maximum number of times to retry a batch on recoverable errors.
	MaxRetries int `json:"maxRetries,omitempty"`
	// MinBackoff is the initial retry delay. Gets doubled for every retry.
	MinBackoff string `json:"minBackoff,omitempty"`
	// MaxBackoff is the maximum retry delay.
	MaxBackoff string `json:"maxBackoff,omitempty"`
	// Retry upon receiving a 429 status code from the remote-write storage.
	// This is experimental feature and might change in the future.
	RetryOnRateLimit bool `json:"retryOnRateLimit,omitempty"`
}

// Sigv4 optionally configures AWS's Signature Verification 4 signing process to
// sign requests.
// +k8s:openapi-gen=true
type Sigv4 struct {
	// Region is the AWS region. If blank, the region from the default credentials chain used.
	Region string `json:"region,omitempty"`
	// AccessKey is the AWS API key. If null, the environment variable `AWS_ACCESS_KEY_ID` is used.
	AccessKey *v1.SecretKeySelector `json:"accessKey,omitempty"`
	// SecretKey is the AWS API secret. If null, the environment variable `AWS_SECRET_ACCESS_KEY` is used.
	SecretKey *v1.SecretKeySelector `json:"secretKey,omitempty"`
	// Profile is the named AWS profile used to authenticate.
	Profile string `json:"profile,omitempty"`
	// RoleArn is the named AWS profile used to authenticate.
	RoleArn string `json:"roleArn,omitempty"`
}

// RemoteReadSpec defines the configuration for Prometheus to read back samples
// from a remote endpoint.
// +k8s:openapi-gen=true
type RemoteReadSpec struct {
	// The URL of the endpoint to query from.
	URL string `json:"url"`
	// The name of the remote read queue, it must be unique if specified. The name
	// is used in metrics and logging in order to differentiate read
	// configurations.  Only valid in Prometheus versions 2.15.0 and newer.
	Name string `json:"name,omitempty"`
	// An optional list of equality matchers which have to be present
	// in a selector to query the remote read endpoint.
	RequiredMatchers map[string]string `json:"requiredMatchers,omitempty"`
	// Timeout for requests to the remote read endpoint.
	RemoteTimeout Duration `json:"remoteTimeout,omitempty"`
	// Custom HTTP headers to be sent along with each remote read request.
	// Be aware that headers that are set by Prometheus itself can't be overwritten.
	// Only valid in Prometheus versions 2.26.0 and newer.
	Headers map[string]string `json:"headers,omitempty"`
	// Whether reads should be made for queries for time ranges that
	// the local storage should have complete data for.
	ReadRecent bool `json:"readRecent,omitempty"`
	// Defines Basic authentication credentials to authenticate against the URL.
	//
	// Cannot be set at the same time as `authorization`, or `oauth2`.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Defines OAuth2 credentials for the URL. Only valid in Prometheus
	// versions 2.27.0 and newer.
	//
	// Cannot be set at the same time as `authorization`, or `basicAuth`.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// Bearer token for remote read.
	//
	// *Warning: this field shouldn't used because the token value appears in
	// clear-text. Use `authorization` instead.*
	//
	// *Deprecated: this will be removed in a future release.*
	BearerToken string `json:"bearerToken,omitempty"`
	// File to read bearer token for remote read.
	//
	// *Deprecated: this will be removed in a future release. Use
	// `authorization` instead.*
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Authorization section for remote read
	//
	// Cannot be set at the same time as `oauth2`, or `basicAuth`.
	Authorization *Authorization `json:"authorization,omitempty"`
	// TLS Config to use for remote read.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Proxy's URL (e.g. 'http://proxyserver:2195') to use for the remote read endpoint.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// Whether to use the external labels as selectors for the remote read endpoint.
	// Requires Prometheus v2.34.0 and above.
	FilterExternalLabels *bool `json:"filterExternalLabels,omitempty"`
}

// LabelName is a valid Prometheus label name which may only contain ASCII letters, numbers, as well as underscores.
// +kubebuilder:validation:Pattern:="^[a-zA-Z_][a-zA-Z0-9_]*$"
type LabelName string

// RelabelConfig allows dynamic rewriting of the label set for targets, alerts, scraped samples and remote write samples.
// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
// +k8s:openapi-gen=true
type RelabelConfig struct {
	// The source labels select values from existing labels. Their content is
	// concatenated using the configured separator and matched against the
	// configured regular expression for the replace, keep, and drop actions.
	SourceLabels []LabelName `json:"sourceLabels,omitempty"`
	// Separator placed between concatenated source label values. default is ';'.
	Separator string `json:"separator,omitempty"`
	// Label to which the resulting value is written in a replace action.  It
	// is mandatory for replace actions. Regex capture groups are available.
	TargetLabel string `json:"targetLabel,omitempty"`
	// Regular expression against which the extracted value is matched. Default is '(.*)'
	Regex string `json:"regex,omitempty"`
	// Modulus to take of the hash of the source label values.
	Modulus uint64 `json:"modulus,omitempty"`
	// Replacement value against which a regex replace is performed if the
	// regular expression matches. Regex capture groups are available.
	Replacement string `json:"replacement,omitempty"`
	// Action to perform based on regex matching. Default is 'replace'.
	// 'uppercase' and 'lowercase' actions require Prometheus >= 2.36.
	//+kubebuilder:validation:Enum=replace;Replace;keep;Keep;drop;Drop;hashmod;HashMod;labelmap;LabelMap;labeldrop;LabelDrop;labelkeep;LabelKeep;lowercase;Lowercase;uppercase;Uppercase
	//+kubebuilder:default=replace
	Action string `json:"action,omitempty"`
}

// APIServerConfig defines how the Prometheus server connects to the Kubernetes API server.
// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config
// +k8s:openapi-gen=true
type APIServerConfig struct {
	// Kubernetes API address consisting of a hostname or IP address followed
	// by an optional port number.
	Host string `json:"host"`
	// Defines Basic authentication credentials to authenticate against the API
	// server.
	// Cannot be set at the same time as `authorization`, `bearerToken`, or
	// `bearerTokenFile`.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Defines a Bearer token to authenticate against the API server.
	// Cannot be set at the same time as `basicAuth`, `authorization`, or
	// `bearerTokenFile`.
	BearerToken string `json:"bearerToken,omitempty"`
	// Defines the file containing the Bearer token to authenticate against the
	// API server.
	// Cannot be set at the same time as `basicAuth`, `authorization`, or `bearerToken`.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// TLS configuration for accessing the API server.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Defines the Authorization header for all requests to the API server.
	// Cannot be set at the same time as `basicAuth`, `bearerToken`, or
	// `bearerTokenFile`.
	Authorization *Authorization `json:"authorization,omitempty"`
}

// AlertmanagerEndpoints defines a selection of a single Endpoints object
// containing Alertmanager IPs to fire alerts against.
// +k8s:openapi-gen=true
type AlertmanagerEndpoints struct {
	// Namespace of the Endpoints object.
	Namespace string `json:"namespace"`
	// Name of the Endpoints object in the namespace.
	Name string `json:"name"`
	// Port on which the Alertmanager API is exposed on.
	Port intstr.IntOrString `json:"port"`
	// Scheme to use when firing alerts.
	Scheme string `json:"scheme,omitempty"`
	// Prefix for the HTTP path alerts are pushed to.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// TLS configuration to use when connecting to Alertmanager.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Defines the file containing the Bearer token to authenticate against the
	// Alertmanager API.
	// Cannot be set at the same time as `authorization`.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Defines the Authorization header for all requests to the Alertmanager
	// API.
	// Cannot be set at the same time as `bearerTokenFile`.
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// Version of the Alertmanager API that Prometheus uses to send alerts. It
	// can be "v1" or "v2".
	// TODO(simonpasquier): add kubebuiler validation.
	APIVersion string `json:"apiVersion,omitempty"`
	// Timeout is a per-target Alertmanager timeout when pushing alerts.
	Timeout *Duration `json:"timeout,omitempty"`
	// Whether to enable HTTP2.
	EnableHttp2 *bool `json:"enableHttp2,omitempty"`
}

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="smon"

// ServiceMonitor defines how to scrape metrics from Pods exposed by a Kubernetes Service.
type ServiceMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of desired Service selection for target discovery by
	// Prometheus.
	Spec ServiceMonitorSpec `json:"spec"`
}

// ServiceMonitorSpec contains specification parameters for a ServiceMonitor.
// +k8s:openapi-gen=true
type ServiceMonitorSpec struct {
	// JobLabel selects the label from the associated Kubernetes service which
	// will be used as the `job` label for all scraped metrics.
	//
	// For example, if a ServiceMonitor object defines `spec.jobLabel: foo` and
	// the associated Kubernetes Service defines `metadata.labels.foo: bar`, then the
	// `job="bar"` label is added to all metrics.
	//
	// If the value of this field is empty or if the label doesn't exist for
	// the given Service, the `job` label of the metrics defaults to the name
	// of the Kubernetes Service.
	JobLabel string `json:"jobLabel,omitempty"`
	// TargetLabels transfers labels from the Kubernetes Service onto the
	// scraped metrics.
	TargetLabels []string `json:"targetLabels,omitempty"`
	// PodTargetLabels transfers labels on the Kubernetes Pods onto the scraped
	// metrics.
	PodTargetLabels []string `json:"podTargetLabels,omitempty"`
	// List of endpoints associated to the ServiceMonitor.
	Endpoints []Endpoint `json:"endpoints"`
	// Selector to select the Endpoints objects.
	Selector metav1.LabelSelector `json:"selector"`
	// Selects from which namespaces the Kubernetes Endpoints objects are
	// discovered from.
	// By default, a ServiceMonitor only matches Endpoints in the same namespace.
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"`
	// Per-scrape limit on number of scraped samples that will be accepted.
	// If more than this number of samples are present after metric relabeling
	// the entire scrape will be treated as failed. 0 means no limit.
	SampleLimit uint64 `json:"sampleLimit,omitempty"`
	// Per-scrape config limit on number of unique targets that will be
	// accepted. If more than this number of targets are present after target
	// relabeling, Prometheus will mark the targets as failed without scraping
	// them. 0 means no limit.
	TargetLimit uint64 `json:"targetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample.
	// If more than this number of labels are present post metric-relabeling,
	// the entire scrape will be treated as failed. 0 means no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelLimit uint64 `json:"labelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a
	// sample.  If a label name is longer than this number post
	// metric-relabeling, the entire scrape will be treated as failed. 0 means
	// no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelNameLengthLimit uint64 `json:"labelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a
	// sample.  If a label value is longer than this number post
	// metric-relabeling, the entire scrape will be treated as failed. 0 means
	// no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelValueLengthLimit uint64 `json:"labelValueLengthLimit,omitempty"`
	// Attaches node metadata to discovered targets.
	// Requires Prometheus v2.37.0 and above.
	AttachMetadata *AttachMetadata `json:"attachMetadata,omitempty"`
}

// Endpoint defines a scrapeable endpoint serving Prometheus metrics.
// +k8s:openapi-gen=true
type Endpoint struct {
	// Name of the Service's port this endpoint refers to.
	// If both `port` and `targetPort` are defined, `port` takes precedence.
	Port string `json:"port,omitempty"`
	// Name or number of the target port exposed by the Pod behind the Service.
	// One of the Pod's containers must define a port property matching this value.
	// If both `port` and `targetPort` are defined, `port` takes precedence.
	TargetPort *intstr.IntOrString `json:"targetPort,omitempty"`
	// HTTP path to scrape for metrics.
	// If empty, Prometheus uses its default value (e.g. `/metrics`).
	Path string `json:"path,omitempty"`
	// HTTP scheme to use for scraping.
	Scheme string `json:"scheme,omitempty"`
	// Optional HTTP URL parameters.
	Params map[string][]string `json:"params,omitempty"`
	// Interval at which metrics should be scraped.
	// If not specified the global scrape interval is used.
	Interval Duration `json:"interval,omitempty"`
	// How long until a scrape request times out.
	// If empty, the global scrape timeout is used unless its value is more
	// than `Interval` in which the latter is used.
	ScrapeTimeout Duration `json:"scrapeTimeout,omitempty"`
	// TLS configuration to use when scraping the endpoint.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Defines the file containing the Bearer token to authenticate against
	// the endpoint.
	// Cannot be set at the same time as `authorization`, `bearerTokenSecret`,
	// `basicAuth`, or `oauth2`.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Defines a key of a Secret containing the Bearer token to authenticate
	// against the endpoint.
	// The secret needs to be in the same namespace as the ServiceMonitor and
	// readable by the Prometheus Operator.
	//
	// Cannot be set at the same time as `authorization`, `bearerTokenFile`,
	// `basicAuth`, or `oauth2`.
	BearerTokenSecret v1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// Defines the Authorization header for all requests to the endpoint.
	//
	// Cannot be set at the same time as `bearerTokenFile`, `bearerTokenSecret`,
	// `basicAuth`, or `oauth2`.
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// HonorLabels chooses the metric's labels on collisions with target labels.
	// It is equivalent to the `honor_labels` field from the Prometheus scrape
	// configuration
	// (https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config).
	HonorLabels bool `json:"honorLabels,omitempty"`
	// HonorTimestamps controls whether Prometheus respects the timestamps
	// present in scraped data.
	// It is equivalent to the `honor_timestamps` field from the Prometheus scrape
	// configuration
	// (https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config).
	HonorTimestamps *bool `json:"honorTimestamps,omitempty"`
	// Defines Basic authentication credentials to authenticate against the endpoint.
	//
	// Cannot be set at the same time as `authorization`, `oauth2`,
	// `bearerTokenFile`, or `bearerTokenSecret`.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// OAuth2 to authenticate against the endpoint. Only valid in Prometheus versions 2.27.0 and newer.
	//
	// Cannot be set at the same time as `authorization`, `basicAuth`,
	// `bearerTokenFile`, or `bearerTokenSecret`.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []*RelabelConfig `json:"metricRelabelings,omitempty"`
	// RelabelConfigs to apply to the samples before scraping.
	//
	// The Prometheus Operator automatically adds the following labels to the scraped targets:
	// * `instance`, the address of the scraped target.
	// * `job`, `{metadata.namespace}/{metadata.name}` unless `spec.jobLabel` is defined.
	// * `namespace`, namespace of the Service being scraped.
	// * `service`, name of the Service being scraped.
	// * `pod`, name of the Pod being scraped.
	// * `container`, name of the container being scraped.
	// * `endpoint`, name of the container's port being scraped.
	// * `node`, name of the node being scraped when the target's kind is Node.
	//
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	//
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []*RelabelConfig `json:"relabelings,omitempty"`
	// Proxy's URL (e.g. 'http://proxyserver:2195') to use when scraping the endpoint.
	ProxyURL *string `json:"proxyUrl,omitempty"`
	// FollowRedirects configures whether scrape requests follow HTTP 3xx redirects.
	FollowRedirects *bool `json:"followRedirects,omitempty"`
	// Whether to enable HTTP2.
	EnableHttp2 *bool `json:"enableHttp2,omitempty"`
	// When true, Prometheus will drop Pods that are not running (e.g. Pods in
	// 'Failed' or 'Succeeded' phases aren't scraped).
	// More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase
	// Default: true.
	FilterRunning *bool `json:"filterRunning,omitempty"`
}

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="pmon"

// PodMonitor defines how to scrape metrics for a set of Pods.
type PodMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of desired Pod selection for target discovery by Prometheus.
	Spec PodMonitorSpec `json:"spec"`
}

// PodMonitorSpec contains specification parameters for a PodMonitor.
// +k8s:openapi-gen=true
type PodMonitorSpec struct {
	// The label to use to retrieve the job name from. See the description of
	// the ServiceMonitor's `spec.jobLabel` field for the details.
	//
	// If the value of this field is empty or if the label doesn't exist for
	// the given Pod, the `job` label of the metrics defaults to
	// `<namespace>/<name of the pod>`.
	JobLabel string `json:"jobLabel,omitempty"`
	// PodTargetLabels transfers labels on the Kubernetes Pods onto the scraped
	// metrics.
	PodTargetLabels []string `json:"podTargetLabels,omitempty"`
	// List of endpoints allowed associated to this PodMonitor.
	PodMetricsEndpoints []PodMetricsEndpoint `json:"podMetricsEndpoints"`
	// Selector to select the Pod objects.
	Selector metav1.LabelSelector `json:"selector"`
	// Selects from which namespaces the Kubernetes Pod objects are
	// discovered from.
	// By default, a PodMonitor only matches Pods in the same namespace.
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"`
	// Per-scrape limit on number of scraped samples that will be accepted.
	// If more than this number of samples are present after metric relabeling
	// the entire scrape will be treated as failed. 0 means no limit.
	SampleLimit uint64 `json:"sampleLimit,omitempty"`
	// Per-scrape config limit on number of unique targets that will be
	// accepted. If more than this number of targets are present after target
	// relabeling, Prometheus will mark the targets as failed without scraping
	// them. 0 means no limit.
	TargetLimit uint64 `json:"targetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample.
	// If more than this number of labels are present post metric-relabeling,
	// the entire scrape will be treated as failed. 0 means no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelLimit uint64 `json:"labelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a
	// sample.  If a label name is longer than this number post
	// metric-relabeling, the entire scrape will be treated as failed. 0 means
	// no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelNameLengthLimit uint64 `json:"labelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a
	// sample.  If a label value is longer than this number post
	// metric-relabeling, the entire scrape will be treated as failed. 0 means
	// no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelValueLengthLimit uint64 `json:"labelValueLengthLimit,omitempty"`
	// Attaches node metadata to discovered targets.
	// Requires Prometheus v2.35.0 and above.
	AttachMetadata *AttachMetadata `json:"attachMetadata,omitempty"`
}

type AttachMetadata struct {
	// When set to true, Prometheus must have permissions to get Nodes.
	Node bool `json:"node,omitempty"`
}

// PodMetricsEndpoint defines a scrapeable endpoint of a Kubernetes Pod serving
// Prometheus metrics.
// +k8s:openapi-gen=true
type PodMetricsEndpoint struct {
	// Name of the Pod's port this endpoint refers to.
	// Mutually exclusive with targetPort.
	Port string `json:"port,omitempty"`
	// *Deprecated: Use 'port' instead.*
	TargetPort *intstr.IntOrString `json:"targetPort,omitempty"`
	// HTTP path to scrape for metrics.
	// If empty, Prometheus uses the default value (e.g. `/metrics`).
	Path string `json:"path,omitempty"`
	// HTTP scheme to use for scraping.
	Scheme string `json:"scheme,omitempty"`
	// Optional HTTP URL parameters.
	Params map[string][]string `json:"params,omitempty"`
	// Interval at which metrics should be scraped
	// If not specified the global scrape interval is used.
	Interval Duration `json:"interval,omitempty"`
	// How long until a scrape request times out.
	// If empty, the global scrape timeout is used unless its value is more
	// than `Interval` in which the latter is used.
	ScrapeTimeout Duration `json:"scrapeTimeout,omitempty"`
	// TLS configuration to use when scraping the endpoint.
	TLSConfig *PodMetricsEndpointTLSConfig `json:"tlsConfig,omitempty"`
	// Secret to mount to read bearer token for scraping targets. The secret
	// needs to be in the same namespace as the PodMonitor and accessible by
	// the Prometheus Operator.
	//
	// Cannot be set at the same time as `authorization`, `basicAuth`,
	// `oauth2`, or `bearerTokenSecret`.
	BearerTokenSecret v1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// HonorLabels chooses the metric's labels on collisions with target labels.
	HonorLabels bool `json:"honorLabels,omitempty"`
	// HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
	HonorTimestamps *bool `json:"honorTimestamps,omitempty"`
	// Defines Basic authentication credentials to authenticate against the endpoint.
	//
	// Cannot be set at the same time as `authorization`, `bearerTokenFile`,
	// `oauth2`, or `bearerTokenSecret`.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// OAuth2 to authenticate against the endpoint. Only valid in Prometheus versions 2.27.0 and newer.
	//
	// Cannot be set at the same time as `authorization`, `basicAuth`,
	// `bearerTokenFile`, or `bearerTokenSecret`.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// Defines the Authorization header for all requests to the endpoint.
	//
	// Cannot be set at the same time as `oauth2`, `basicAuth`,
	// `bearerTokenFile`, or `bearerTokenSecret`.
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []*RelabelConfig `json:"metricRelabelings,omitempty"`
	// RelabelConfigs to apply to the samples before scraping.
	//
	// The Prometheus Operator automatically adds the following labels to the scraped targets:
	// * `instance`, the address of the scraped target.
	// * `job`, `{metadata.namespace}/{metadata.name}` unless `spec.jobLabel` is defined.
	// * `namespace`, namespace of the Pod being scraped.
	// * `pod`, name of the Pod being scraped.
	// * `container`, name of the container being scraped.
	// * `endpoint`, name of the container's port being scraped.
	//
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	//
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []*RelabelConfig `json:"relabelings,omitempty"`
	// Proxy URL (e.g. 'http://proxyserver:2195') to use when scraping the endpoint.
	ProxyURL *string `json:"proxyUrl,omitempty"`
	// FollowRedirects configures whether scrape requests follow HTTP 3xx redirects.
	FollowRedirects *bool `json:"followRedirects,omitempty"`
	// Whether to enable HTTP2.
	EnableHttp2 *bool `json:"enableHttp2,omitempty"`
	// When true, Prometheus will drop Pods that are not running (e.g. Pods in
	// 'Failed' or 'Succeeded' phases aren't scraped).
	// More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase
	// Default: true.
	FilterRunning *bool `json:"filterRunning,omitempty"`
}

// PodMetricsEndpointTLSConfig specifies the TLS configuration parameters.
// +k8s:openapi-gen=true
type PodMetricsEndpointTLSConfig struct {
	SafeTLSConfig `json:",inline"`
}

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="prb"

// Probe defines how to probe endpoints (eiher a set of static targets or
// Kubernetes Ingress objects).
// It requires the deployment of a prober, typically the Prometheus blackbox
// exporter (https://github.com/prometheus/blackbox_exporter).
type Probe struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of desired Ingress selection for target discovery by Prometheus.
	Spec ProbeSpec `json:"spec"`
}

// ProbeSpec contains specification parameters for a Probe.
// +k8s:openapi-gen=true
type ProbeSpec struct {
	// The default `job` label's value for scraped metrics.
	JobName string `json:"jobName,omitempty"`
	// Specification for the prober to use for probing targets.
	// No targets will be probed if this field is empty.
	ProberSpec ProberSpec `json:"prober,omitempty"`
	// The module to use for probing specifying how to probe the target.
	// Examples of module configuration for the blackbox exporter can be found
	// in https://github.com/prometheus/blackbox_exporter/blob/master/example.yml.
	Module string `json:"module,omitempty"`
	// Targets defines a set of static or dynamically discovered targets to probe.
	Targets ProbeTargets `json:"targets,omitempty"`
	// Interval at which targets are probed using the configured prober.
	// If not specified Prometheus' global scrape interval is used.
	Interval Duration `json:"interval,omitempty"`
	// How long until a scrape request times out.
	// If empty, the global scrape timeout is used unless its value is more
	// than `Interval` in which the latter is used.
	ScrapeTimeout Duration `json:"scrapeTimeout,omitempty"`
	// TLS configuration to use when scraping the prober.
	TLSConfig *ProbeTLSConfig `json:"tlsConfig,omitempty"`
	// Secret to mount to read bearer token for scraping the prober. The secret
	// needs to be in the same namespace as the Probe and accessible by
	// the Prometheus Operator.
	//
	// Cannot be set at the same time as `authorization`, `basicAuth`, or
	// `bearerTokenSecret`.
	BearerTokenSecret v1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// Defines Basic authentication credentials to authenticate against the prober.
	//
	// Cannot be set at the same time as `authorization`, `oauth2`, or
	// `bearerTokenSecret`.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// OAuth2 to authenticate against the prober. Only valid in Prometheus versions 2.27.0 and newer.
	//
	// Cannot be set at the same time as `authorization`, `basicAuth`, or
	// `bearerTokenSecret`.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []*RelabelConfig `json:"metricRelabelings,omitempty"`
	// Defines the Authorization header for all requests to the prober.
	//
	// Cannot be set at the same time as `oauth2`, `basicAuth`, or
	// `bearerTokenSecret`.
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// Per-scrape limit on number of scraped samples that will be accepted.
	// If more than this number of samples are present after metric relabeling
	// the entire scrape will be treated as failed. 0 means no limit.
	SampleLimit uint64 `json:"sampleLimit,omitempty"`
	// Per-scrape config limit on number of unique targets that will be
	// accepted. If more than this number of targets are present after target
	// relabeling, Prometheus will mark the targets as failed without scraping
	// them. 0 means no limit.
	TargetLimit uint64 `json:"targetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample.
	// If more than this number of labels are present post metric-relabeling,
	// the entire scrape will be treated as failed. 0 means no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelLimit uint64 `json:"labelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a
	// sample.  If a label name is longer than this number post
	// metric-relabeling, the entire scrape will be treated as failed. 0 means
	// no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelNameLengthLimit uint64 `json:"labelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a
	// sample.  If a label value is longer than this number post
	// metric-relabeling, the entire scrape will be treated as failed. 0 means
	// no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelValueLengthLimit uint64 `json:"labelValueLengthLimit,omitempty"`
}

// ProbeTargets defines how to discover the probed targets.
// One of the `staticConfig` or `ingress` must be defined.
// If both are defined, `staticConfig` takes precedence.
// +k8s:openapi-gen=true
type ProbeTargets struct {
	// Defines the static list of targets to probe and their relabeling
	// configuration.
	// If `ingress` is also defined, `staticConfig` takes precedence.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#static_config.
	StaticConfig *ProbeTargetStaticConfig `json:"staticConfig,omitempty"`
	// Defines the Ingress objects to probe and the relabeling configuration.
	// If `staticConfig` is also defined, `staticConfig` takes precedence.
	Ingress *ProbeTargetIngress `json:"ingress,omitempty"`
}

// Validate semantically validates the given ProbeTargets.
func (it *ProbeTargets) Validate() error {
	if it.StaticConfig == nil && it.Ingress == nil {
		return &ProbeTargetsValidationError{"at least one of .spec.targets.staticConfig and .spec.targets.ingress is required"}
	}

	return nil
}

// ProbeTargetsValidationError is returned by ProbeTargets.Validate()
// on semantically invalid configurations.
// +k8s:openapi-gen=false
type ProbeTargetsValidationError struct {
	err string
}

func (e *ProbeTargetsValidationError) Error() string {
	return e.err
}

// ProbeTargetStaticConfig defines the set of static targets considered for probing.
// +k8s:openapi-gen=true
type ProbeTargetStaticConfig struct {
	// The list of hosts to probe.
	// For example: ['http://example.com', 'https://example.com/']
	Targets []string `json:"static,omitempty"`
	// Labels assigned to all metrics scraped from the targets.
	Labels map[string]string `json:"labels,omitempty"`
	// RelabelConfigs to apply to the label set of the targets before it gets
	// probed.
	//
	// The Prometheus Operator automatically adds the following labels:
	// * `instance`, the address of the probed target.
	// * `namespace`, namespace of the Probe object.
	//
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []*RelabelConfig `json:"relabelingConfigs,omitempty"`
}

// ProbeTargetIngress defines the set of Ingress objects considered for probing.
// The operator configures a target for each host/path combination of each ingress object.
// +k8s:openapi-gen=true
type ProbeTargetIngress struct {
	// Selector to select the Ingress objects.
	Selector metav1.LabelSelector `json:"selector,omitempty"`
	// Selects from which namespaces the Kubernetes Ingress objects are
	// discovered from.
	// By default, a Probe only matches Ingress objects in the same namespace.
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"`
	// RelabelConfigs to apply to the label set of the target before it gets
	// scraped.
	//
	// The Prometheus Operator automatically adds the following labels:
	// * `instance`, the address of the probed target.
	// * `namespace`, namespace of the Ingress object.
	// * `ingress`, name of the Ingress object.
	//
	// The original Ingress' address is available via the
	// `__tmp_prometheus_ingress_address` label. It can be used to customize the
	// probed URL.
	//
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []*RelabelConfig `json:"relabelingConfigs,omitempty"`
}

// ProberSpec contains specification parameters for the Prober used for probing.
// +k8s:openapi-gen=true
type ProberSpec struct {
	// Mandatory URL of the prober.
	// TODO(simonpasquier): add kubebuilder validations.
	URL string `json:"url"`
	// HTTP scheme to use for scraping.
	// Defaults to `http`.
	// TODO(simonpasquier): add kubebuilder validations.
	Scheme string `json:"scheme,omitempty"`
	// Path to collect metrics from.
	// Defaults to `/probe`.
	// +kubebuilder:default:="/probe"
	Path string `json:"path,omitempty"`
	// Proxy's URL (e.g. 'http://proxyserver:2195') to use when scraping the prober.
	ProxyURL string `json:"proxyUrl,omitempty"`
}

// OAuth2 defines how to authenticate against an endpoint using OAuth2.
// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#oauth2
// +k8s:openapi-gen=true
type OAuth2 struct {
	// The secret or configmap containing the OAuth2 client id.
	ClientID SecretOrConfigMap `json:"clientId"`
	// The secret containing the OAuth2 client secret.
	ClientSecret v1.SecretKeySelector `json:"clientSecret"`
	// The URL to fetch the token from.
	// +kubebuilder:validation:MinLength=1
	TokenURL string `json:"tokenUrl"`
	// OAuth2 scopes used for the token request.
	Scopes []string `json:"scopes,omitempty"`
	// Parameters to append to the token URL.
	EndpointParams map[string]string `json:"endpointParams,omitempty"`
}

type OAuth2ValidationError struct {
	err string
}

func (e *OAuth2ValidationError) Error() string {
	return e.err
}

func (o *OAuth2) Validate() error {
	if o.TokenURL == "" {
		return &OAuth2ValidationError{err: "OAuth2 token url must be specified"}
	}

	if o.ClientID == (SecretOrConfigMap{}) {
		return &OAuth2ValidationError{err: "OAuth2 client id must be specified"}
	}

	if err := o.ClientID.Validate(); err != nil {
		return &OAuth2ValidationError{
			err: fmt.Sprintf("invalid OAuth2 client id: %s", err.Error()),
		}
	}

	return nil
}

// BasicAuth defines the credentials to authenticate using basic authentication.
// +k8s:openapi-gen=true
type BasicAuth struct {
	// The secret in the object's namespace that contains the username
	// for authentication.
	Username v1.SecretKeySelector `json:"username,omitempty"`
	// The secret in the objects namespace that contains the password
	// for authentication.
	Password v1.SecretKeySelector `json:"password,omitempty"`
}

// SecretOrConfigMap allows to specify data as a Secret or ConfigMap. Fields are mutually exclusive.
type SecretOrConfigMap struct {
	// Secret containing data to use for the targets.
	Secret *v1.SecretKeySelector `json:"secret,omitempty"`
	// ConfigMap containing data to use for the targets.
	ConfigMap *v1.ConfigMapKeySelector `json:"configMap,omitempty"`
}

// SecretOrConfigMapValidationError is returned by SecretOrConfigMap.Validate()
// on semantically invalid configurations.
// +k8s:openapi-gen=false
type SecretOrConfigMapValidationError struct {
	err string
}

func (e *SecretOrConfigMapValidationError) Error() string {
	return e.err
}

// Validate semantically validates the given TLSConfig.
func (c *SecretOrConfigMap) Validate() error {
	if c.Secret != nil && c.ConfigMap != nil {
		return &SecretOrConfigMapValidationError{"SecretOrConfigMap can not specify both Secret and ConfigMap"}
	}

	return nil
}

// SafeTLSConfig specifies safe TLS configuration parameters.
// +k8s:openapi-gen=true
type SafeTLSConfig struct {
	// Certificate authority used when verifying server certificates.
	CA SecretOrConfigMap `json:"ca,omitempty"`
	// Client certificate to present when doing client-authentication.
	Cert SecretOrConfigMap `json:"cert,omitempty"`
	// Secret containing the client key file for the targets.
	KeySecret *v1.SecretKeySelector `json:"keySecret,omitempty"`
	// Used to verify the hostname for the targets.
	ServerName string `json:"serverName,omitempty"`
	// Disable target certificate validation.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// Validate semantically validates the given SafeTLSConfig.
func (c *SafeTLSConfig) Validate() error {
	if c.CA != (SecretOrConfigMap{}) {
		if err := c.CA.Validate(); err != nil {
			return err
		}
	}

	if c.Cert != (SecretOrConfigMap{}) {
		if err := c.Cert.Validate(); err != nil {
			return err
		}
	}

	if c.Cert != (SecretOrConfigMap{}) && c.KeySecret == nil {
		return &TLSConfigValidationError{"client cert specified without client key"}
	}

	if c.KeySecret != nil && c.Cert == (SecretOrConfigMap{}) {
		return &TLSConfigValidationError{"client key specified without client cert"}
	}

	return nil
}

// TLSConfig extends the safe TLS configuration with file parameters.
// +k8s:openapi-gen=true
type TLSConfig struct {
	SafeTLSConfig `json:",inline"`
	// Path to the CA cert in the Prometheus container to use for the targets.
	CAFile string `json:"caFile,omitempty"`
	// Path to the client cert file in the Prometheus container for the targets.
	CertFile string `json:"certFile,omitempty"`
	// Path to the client key file in the Prometheus container for the targets.
	KeyFile string `json:"keyFile,omitempty"`
}

// TLSConfigValidationError is returned by TLSConfig.Validate() on semantically
// invalid tls configurations.
// +k8s:openapi-gen=false
type TLSConfigValidationError struct {
	err string
}

func (e *TLSConfigValidationError) Error() string {
	return e.err
}

// Validate semantically validates the given TLSConfig.
func (c *TLSConfig) Validate() error {
	if c.CA != (SecretOrConfigMap{}) {
		if c.CAFile != "" {
			return &TLSConfigValidationError{"tls config can not both specify CAFile and CA"}
		}
		if err := c.CA.Validate(); err != nil {
			return &TLSConfigValidationError{"tls config CA is invalid"}
		}
	}

	if c.Cert != (SecretOrConfigMap{}) {
		if c.CertFile != "" {
			return &TLSConfigValidationError{"tls config can not both specify CertFile and Cert"}
		}
		if err := c.Cert.Validate(); err != nil {
			return &TLSConfigValidationError{"tls config Cert is invalid"}
		}
	}

	if c.KeyFile != "" && c.KeySecret != nil {
		return &TLSConfigValidationError{"tls config can not both specify KeyFile and KeySecret"}
	}

	hasCert := c.CertFile != "" || c.Cert != (SecretOrConfigMap{})
	hasKey := c.KeyFile != "" || c.KeySecret != nil

	if hasCert && !hasKey {
		return &TLSConfigValidationError{"tls config can not specify client cert without client key"}
	}

	if hasKey && !hasCert {
		return &TLSConfigValidationError{"tls config can not specify client key without client cert"}
	}

	return nil
}

// ServiceMonitorList is a list of ServiceMonitors.
// +k8s:openapi-gen=true
type ServiceMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of ServiceMonitors
	Items []*ServiceMonitor `json:"items"`
}

// PodMonitorList is a list of PodMonitors.
// +k8s:openapi-gen=true
type PodMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of PodMonitors
	Items []*PodMonitor `json:"items"`
}

// ProbeList is a list of Probes.
// +k8s:openapi-gen=true
type ProbeList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of Probes
	Items []*Probe `json:"items"`
}

// PrometheusRuleList is a list of PrometheusRules.
// +k8s:openapi-gen=true
type PrometheusRuleList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of Rules
	Items []*PrometheusRule `json:"items"`
}

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="promrule"

// PrometheusRule defines recording and alerting rules for a Prometheus instance
type PrometheusRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of desired alerting rule definitions for Prometheus.
	Spec PrometheusRuleSpec `json:"spec"`
}

// PrometheusRuleSpec contains specification parameters for a Rule.
// +k8s:openapi-gen=true
type PrometheusRuleSpec struct {
	// Content of Prometheus rule file
	// +listType=map
	// +listMapKey=name
	Groups []RuleGroup `json:"groups,omitempty"`
}

// RuleGroup and Rule are copied instead of vendored because the
// upstream Prometheus struct definitions don't have json struct tags.

// RuleGroup is a list of sequentially evaluated recording and alerting rules.
// +k8s:openapi-gen=true
type RuleGroup struct {
	// Name of the rule group.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Interval determines how often rules in the group are evaluated.
	Interval Duration `json:"interval,omitempty"`
	// List of alerting and recording rules.
	Rules []Rule `json:"rules"`
	// PartialResponseStrategy is only used by ThanosRuler and will
	// be ignored by Prometheus instances.
	// More info: https://github.com/thanos-io/thanos/blob/main/docs/components/rule.md#partial-response
	// +kubebuilder:validation:Pattern="^(?i)(abort|warn)?$"
	// +kubebuilder:default:=""
	PartialResponseStrategy string `json:"partial_response_strategy,omitempty"`
}

// Rule describes an alerting or recording rule
// See Prometheus documentation: [alerting](https://www.prometheus.io/docs/prometheus/latest/configuration/alerting_rules/) or [recording](https://www.prometheus.io/docs/prometheus/latest/configuration/recording_rules/#recording-rules) rule
// +k8s:openapi-gen=true
type Rule struct {
	// Name of the time series to output to. Must be a valid metric name.
	// Only one of `record` and `alert` must be set.
	Record string `json:"record,omitempty"`
	// Name of the alert. Must be a valid label value.
	// Only one of `record` and `alert` must be set.
	Alert string `json:"alert,omitempty"`
	// PromQL expression to evaluate.
	Expr intstr.IntOrString `json:"expr"`
	// Alerts are considered firing once they have been returned for this long.
	For Duration `json:"for,omitempty"`
	// Labels to add or overwrite.
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations to add to each alert.
	// Only valid for alerting rules.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="am"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version",description="The version of Alertmanager"
// +kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".spec.replicas",description="The number of desired replicas"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Paused",type="boolean",JSONPath=".status.paused",description="Whether the resource reconciliation is paused or not",priority=1

// Alertmanager describes an Alertmanager cluster.
type Alertmanager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the Alertmanager cluster. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec AlertmanagerSpec `json:"spec"`
	// Most recent observed status of the Alertmanager cluster. Read-only. Not
	// included when requesting from the apiserver, only from the Prometheus
	// Operator API itself. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status *AlertmanagerStatus `json:"status,omitempty"`
}

// AlertmanagerSpec is a specification of the desired behavior of the Alertmanager cluster. More info:
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
// +k8s:openapi-gen=true
type AlertmanagerSpec struct {
	// PodMetadata configures Labels and Annotations which are propagated to the alertmanager pods.
	PodMetadata *EmbeddedObjectMetadata `json:"podMetadata,omitempty"`
	// Container image name for Alertmanager. If specified, it takes precedence
	// over the `spec.baseImage`, `spec.tag` and `spec.sha` fields.
	// Specifying `spec.version` is still necessary to ensure the Prometheus
	// Operator knows which version of Alertmanager is being configured.
	// If neither `spec.image` nor `spec.baseImage` are
	// defined, the operator will use the latest upstream version of
	// Alertmanager available at the time when the operator was released.
	Image *string `json:"image,omitempty"`
	// Version of Alertmanager being deployed. If not specified, the operator
	// assumes the latest upstream version of Alertmanager available at the
	// time when the version of the operator was released.
	Version string `json:"version,omitempty"`
	// *Deprecated: use 'spec.image' instead. The image's tag can be specified
	// as part of the image name.*
	Tag string `json:"tag,omitempty"`
	// *Deprecated: use 'spec.image' instead. The image's digest can be specified
	// as part of the image name.*
	SHA string `json:"sha,omitempty"`
	// *Deprecated: use 'spec.image' instead.*
	BaseImage string `json:"baseImage,omitempty"`
	// An optional list of references to secrets in the same namespace
	// to use for pulling images from registries
	// see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Secrets is a list of Secrets in the same namespace as the Alertmanager
	// object, which shall be mounted into the Alertmanager Pods.
	// Each Secret is added to the StatefulSet definition as a volume named `secret-<secret-name>`.
	// The Secrets are mounted into `/etc/alertmanager/secrets/<secret-name>` in the 'alertmanager' container.
	Secrets []string `json:"secrets,omitempty"`
	// ConfigMaps is a list of ConfigMaps in the same namespace as the Alertmanager
	// object, which shall be mounted into the Alertmanager Pods.
	// Each ConfigMap is added to the StatefulSet definition as a volume named `configmap-<configmap-name>`.
	// The ConfigMaps are mounted into `/etc/alertmanager/configmaps/<configmap-name>` in the 'alertmanager' container.
	ConfigMaps []string `json:"configMaps,omitempty"`
	// ConfigSecret is the name of a Kubernetes Secret in the same namespace as the
	// Alertmanager object, which contains the configuration for this Alertmanager
	// instance. If empty, it defaults to `alertmanager-<alertmanager-name>`.
	//
	// The Alertmanager configuration should be available under the
	// `alertmanager.yaml` key. Additional keys from the original secret are
	// copied to the generated secret and mounted into the
	// `/etc/alertmanager/config` directory in the `alertmanager` container.
	//
	// If either the secret or the `alertmanager.yaml` key is missing, the
	// operator provisions a minimal Alertmanager configuration with one empty
	// receiver (effectively dropping alert notifications).
	ConfigSecret string `json:"configSecret,omitempty"`
	// Log level for Alertmanager to be configured with.
	//+kubebuilder:validation:Enum="";debug;info;warn;error
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for Alertmanager to be configured with.
	//+kubebuilder:validation:Enum="";logfmt;json
	LogFormat string `json:"logFormat,omitempty"`
	// Size is the expected size of the alertmanager cluster. The controller will
	// eventually make the size of the running cluster equal to the expected
	// size.
	Replicas *int32 `json:"replicas,omitempty"`
	// Time duration Alertmanager shall retain data for. Default is '120h',
	// and must match the regular expression `[0-9]+(ms|s|m|h)` (milliseconds seconds minutes hours).
	// +kubebuilder:default:="120h"
	Retention GoDuration `json:"retention,omitempty"`
	// Storage is the definition of how storage will be used by the Alertmanager
	// instances.
	Storage *StorageSpec `json:"storage,omitempty"`
	// Volumes allows configuration of additional volumes on the output StatefulSet definition.
	// Volumes specified will be appended to other volumes that are generated as a result of
	// StorageSpec objects.
	Volumes []v1.Volume `json:"volumes,omitempty"`
	// VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
	// VolumeMounts specified will be appended to other VolumeMounts in the alertmanager container,
	// that are generated as a result of StorageSpec objects.
	VolumeMounts []v1.VolumeMount `json:"volumeMounts,omitempty"`
	// The external URL the Alertmanager instances will be available under. This is
	// necessary to generate correct URLs. This is necessary if Alertmanager is not
	// served from root of a DNS name.
	ExternalURL string `json:"externalUrl,omitempty"`
	// The route prefix Alertmanager registers HTTP handlers for. This is useful,
	// if using ExternalURL and a proxy is rewriting HTTP routes of a request,
	// and the actual ExternalURL is still true, but the server serves requests
	// under a different route prefix. For example for use with `kubectl proxy`.
	RoutePrefix string `json:"routePrefix,omitempty"`
	// If set to true all actions on the underlying managed objects are not
	// goint to be performed, except for delete actions.
	Paused bool `json:"paused,omitempty"`
	// Define which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Define the resources requests and limits of the 'thanos-sidecar' container.
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
	// If specified, the pod's scheduling constraints.
	Affinity *v1.Affinity `json:"affinity,omitempty"`
	// If specified, the pod's tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// If specified, the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// SecurityContext holds pod-level security attributes and common container settings.
	// This defaults to the default PodSecurityContext.
	SecurityContext *v1.PodSecurityContext `json:"securityContext,omitempty"`
	// ServiceAccountName is the name of the ServiceAccount to use to run the
	// Prometheus Pods.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// ListenLocal makes the Alertmanager server listen on loopback, so that it
	// does not bind against the Pod IP. Note this is only for the Alertmanager
	// UI, not the gossip communication.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// Containers allows injecting additional containers. This is meant to
	// allow adding an authentication proxy to an Alertmanager pod.
	// Containers described here modify an operator generated container if they
	// share the same name and modifications are done via a strategic merge
	// patch. The current container names are: `alertmanager` and
	// `config-reloader`. Overriding containers is entirely outside the scope
	// of what the maintainers will support and by doing so, you accept that
	// this behaviour may break at any time without notice.
	Containers []v1.Container `json:"containers,omitempty"`
	// InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
	// fetch secrets for injection into the Alertmanager configuration from external sources. Any
	// errors during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
	// Using initContainers for any use case other then secret fetching is entirely outside the scope
	// of what the maintainers will support and by doing so, you accept that this behaviour may break
	// at any time without notice.
	InitContainers []v1.Container `json:"initContainers,omitempty"`
	// Priority class assigned to the Pods
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// AdditionalPeers allows injecting a set of additional Alertmanagers to peer with to form a highly available cluster.
	AdditionalPeers []string `json:"additionalPeers,omitempty"`
	// ClusterAdvertiseAddress is the explicit address to advertise in cluster.
	// Needs to be provided for non RFC1918 [1] (public) addresses.
	// [1] RFC1918: https://tools.ietf.org/html/rfc1918
	ClusterAdvertiseAddress string `json:"clusterAdvertiseAddress,omitempty"`
	// Interval between gossip attempts.
	ClusterGossipInterval GoDuration `json:"clusterGossipInterval,omitempty"`
	// Interval between pushpull attempts.
	ClusterPushpullInterval GoDuration `json:"clusterPushpullInterval,omitempty"`
	// Timeout for cluster peering.
	ClusterPeerTimeout GoDuration `json:"clusterPeerTimeout,omitempty"`
	// Port name used for the pods and governing service.
	// This defaults to web
	PortName string `json:"portName,omitempty"`
	// ForceEnableClusterMode ensures Alertmanager does not deactivate the cluster mode when running with a single replica.
	// Use case is e.g. spanning an Alertmanager cluster across Kubernetes clusters with a single replica in each.
	ForceEnableClusterMode bool `json:"forceEnableClusterMode,omitempty"`
	// AlertmanagerConfigs to be selected for to merge and configure Alertmanager with.
	AlertmanagerConfigSelector *metav1.LabelSelector `json:"alertmanagerConfigSelector,omitempty"`
	// Namespaces to be selected for AlertmanagerConfig discovery. If nil, only
	// check own namespace.
	AlertmanagerConfigNamespaceSelector *metav1.LabelSelector `json:"alertmanagerConfigNamespaceSelector,omitempty"`
	// Minimum number of seconds for which a newly created pod should be ready
	// without any of its container crashing for it to be considered available.
	// Defaults to 0 (pod will be considered available as soon as it is ready)
	// This is an alpha field and requires enabling StatefulSetMinReadySeconds feature gate.
	// +optional
	MinReadySeconds *uint32 `json:"minReadySeconds,omitempty"`
	// Pods' hostAliases configuration
	// +listType=map
	// +listMapKey=ip
	HostAliases []HostAlias `json:"hostAliases,omitempty"`
	// Defines the web command line flags when starting Alertmanager.
	Web *AlertmanagerWebSpec `json:"web,omitempty"`
	// EXPERIMENTAL: alertmanagerConfiguration specifies the configuration of Alertmanager.
	// If defined, it takes precedence over the `configSecret` field.
	// This field may change in future releases.
	AlertmanagerConfiguration *AlertmanagerConfiguration `json:"alertmanagerConfiguration,omitempty"`
}

// AlertmanagerConfiguration defines the Alertmanager configuration.
// +k8s:openapi-gen=true
type AlertmanagerConfiguration struct {
	// The name of the AlertmanagerConfig resource which is used to generate the Alertmanager configuration.
	// It must be defined in the same namespace as the Alertmanager object.
	// The operator will not enforce a `namespace` label for routes and inhibition rules.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
	// Defines the global parameters of the Alertmanager configuration.
	// +optional
	Global *AlertmanagerGlobalConfig `json:"global,omitempty"`
	// Custom notification templates.
	// +optional
	Templates []SecretOrConfigMap `json:"templates,omitempty"`
}

// AlertmanagerGlobalConfig configures parameters that are valid in all other configuration contexts.
// See https://prometheus.io/docs/alerting/latest/configuration/#configuration-file
type AlertmanagerGlobalConfig struct {
	// ResolveTimeout is the default value used by alertmanager if the alert does
	// not include EndsAt, after this time passes it can declare the alert as resolved if it has not been updated.
	// This has no impact on alerts from Prometheus, as they always include EndsAt.
	ResolveTimeout Duration `json:"resolveTimeout,omitempty"`

	// HTTP client configuration.
	HTTPConfig *HTTPConfig `json:"httpConfig,omitempty"`
}

// HTTPConfig defines a client HTTP configuration.
// See https://prometheus.io/docs/alerting/latest/configuration/#http_config
type HTTPConfig struct {
	// Authorization header configuration for the client.
	// This is mutually exclusive with BasicAuth and is only available starting from Alertmanager v0.22+.
	// +optional
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// BasicAuth for the client.
	// This is mutually exclusive with Authorization. If both are defined, BasicAuth takes precedence.
	// +optional
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// OAuth2 client credentials used to fetch a token for the targets.
	// +optional
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// The secret's key that contains the bearer token to be used by the client
	// for authentication.
	// The secret needs to be in the same namespace as the Alertmanager
	// object and accessible by the Prometheus Operator.
	// +optional
	BearerTokenSecret *v1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// TLS configuration for the client.
	// +optional
	TLSConfig *SafeTLSConfig `json:"tlsConfig,omitempty"`
	// Optional proxy URL.
	// +optional
	ProxyURL string `json:"proxyURL,omitempty"`
	// FollowRedirects specifies whether the client should follow HTTP 3xx redirects.
	// +optional
	FollowRedirects *bool `json:"followRedirects,omitempty"`
}

// AlertmanagerList is a list of Alertmanagers.
// +k8s:openapi-gen=true
type AlertmanagerList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of Alertmanagers
	Items []Alertmanager `json:"items"`
}

// MetadataConfig configures the sending of series metadata to the remote storage.
// +k8s:openapi-gen=true
type MetadataConfig struct {
	// Whether metric metadata is sent to the remote storage or not.
	Send bool `json:"send,omitempty"`
	// How frequently metric metadata is sent to the remote storage.
	SendInterval Duration `json:"sendInterval,omitempty"`
}

// AlertmanagerStatus is the most recent observed status of the Alertmanager cluster. Read-only. Not
// included when requesting from the apiserver, only from the Prometheus
// Operator API itself. More info:
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
// +k8s:openapi-gen=true
type AlertmanagerStatus struct {
	// Represents whether any actions on the underlying managed objects are
	// being performed. Only delete actions will be performed.
	Paused bool `json:"paused"`
	// Total number of non-terminated pods targeted by this Alertmanager
	// cluster (their labels match the selector).
	Replicas int32 `json:"replicas"`
	// Total number of non-terminated pods targeted by this Alertmanager
	// cluster that have the desired version spec.
	UpdatedReplicas int32 `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this Alertmanager cluster.
	AvailableReplicas int32 `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this Alertmanager cluster.
	UnavailableReplicas int32 `json:"unavailableReplicas"`
}

// NamespaceSelector is a selector for selecting either all namespaces or a
// list of namespaces.
// If `any` is true, it takes precedence over `matchNames`.
// If `matchNames` is empty and `any` is false, it means that the objects are
// selected from the current namespace.
// +k8s:openapi-gen=true
type NamespaceSelector struct {
	// Boolean describing whether all namespaces are selected in contrast to a
	// list restricting them.
	Any bool `json:"any,omitempty"`
	// List of namespace names to select from.
	MatchNames []string `json:"matchNames,omitempty"`

	// TODO(fabxc): this should embed metav1.LabelSelector eventually.
	// Currently the selector is only used for namespaces which require more complex
	// implementation to support label selections.
}

// /--rules.*/ command-line arguments
// +k8s:openapi-gen=true
type Rules struct {
	Alert RulesAlert `json:"alert,omitempty"`
}

// /--rules.alert.*/ command-line arguments
// +k8s:openapi-gen=true
type RulesAlert struct {
	// Max time to tolerate prometheus outage for restoring 'for' state of alert.
	ForOutageTolerance string `json:"forOutageTolerance,omitempty"`
	// Minimum duration between alert and restored 'for' state.
	// This is maintained only for alerts with configured 'for' time greater than grace period.
	ForGracePeriod string `json:"forGracePeriod,omitempty"`
	// Minimum amount of time to wait before resending an alert to Alertmanager.
	ResendDelay string `json:"resendDelay,omitempty"`
}

// DeepCopyObject implements the runtime.Object interface.
func (l *Alertmanager) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *AlertmanagerList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *Prometheus) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *PrometheusList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *ServiceMonitor) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *ServiceMonitorList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *PodMonitor) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *PodMonitorList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *Probe) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *ProbeList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (f *PrometheusRule) DeepCopyObject() runtime.Object {
	return f.DeepCopy()
}

// DeepCopyObject implements the runtime.Object interface.
func (l *PrometheusRuleList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// ProbeTLSConfig specifies TLS configuration parameters for the prober.
// +k8s:openapi-gen=true
type ProbeTLSConfig struct {
	SafeTLSConfig `json:",inline"`
}

// SafeAuthorization specifies a subset of the Authorization struct, that is
// safe for use in Endpoints (no CredentialsFile field)
// +k8s:openapi-gen=true
type SafeAuthorization struct {
	// Set the authentication type. Defaults to Bearer, Basic will cause an
	// error
	Type string `json:"type,omitempty"`
	// The secret's key that contains the credentials of the request
	Credentials *v1.SecretKeySelector `json:"credentials,omitempty"`
}

// Validate semantically validates the given Authorization section.
func (c *SafeAuthorization) Validate() error {
	if c == nil {
		return nil
	}

	if strings.ToLower(strings.TrimSpace(c.Type)) == "basic" {
		return &AuthorizationValidationError{`Authorization type cannot be set to "basic", use "basic_auth" instead`}
	}
	if c.Credentials == nil {
		return &AuthorizationValidationError{"Authorization credentials are required"}
	}
	return nil
}

// Authorization contains optional `Authorization` header configuration.
// This section is only understood by versions of Prometheus >= 2.26.0.
type Authorization struct {
	SafeAuthorization `json:",inline"`
	// File to read a secret from, mutually exclusive with Credentials (from SafeAuthorization)
	CredentialsFile string `json:"credentialsFile,omitempty"`
}

// Validate semantically validates the given Authorization section.
func (c *Authorization) Validate() error {
	if c.Credentials != nil && c.CredentialsFile != "" {
		return &AuthorizationValidationError{"Authorization can not specify both Credentials and CredentialsFile"}
	}
	if strings.ToLower(strings.TrimSpace(c.Type)) == "basic" {
		return &AuthorizationValidationError{"Authorization type cannot be set to \"basic\", use \"basic_auth\" instead"}
	}
	return nil
}

// AuthorizationValidationError is returned by Authorization.Validate()
// on semantically invalid configurations.
// +k8s:openapi-gen=false
type AuthorizationValidationError struct {
	err string
}

func (e *AuthorizationValidationError) Error() string {
	return e.err
}

// Argument as part of the AdditionalArgs list.
// +k8s:openapi-gen=true
type Argument struct {
	// Name of the argument, e.g. "scrape.discovery-reload-interval".
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Argument value, e.g. 30s. Can be empty for name-only arguments (e.g. --storage.tsdb.no-lockfile)
	Value string `json:"value,omitempty"`
}
