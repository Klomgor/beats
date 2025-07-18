// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/protobuf/types/known/durationpb"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/x-pack/metricbeat/module/gcp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	// MetricsetName is the name of this Metricset
	MetricsetName = "metrics"
)

// init registers the MetricSet with the central registry as soon as the program
// starts. The New function will be called later to instantiate an instance of
// the MetricSet for each host defined in the module's configuration. After the
// MetricSet has been created then Fetch will begin to be called periodically.
func init() {
	mb.Registry.MustAddMetricSet(gcp.ModuleName, MetricsetName, New)
}

// MetricSet holds any configuration or state information. It must implement
// the mb.MetricSet interface. And this is best achieved by embedding
// mb.BaseMetricSet because it implements all of the required mb.MetricSet
// interface methods except for Fetch.
type MetricSet struct {
	mb.BaseMetricSet
	config                config
	metricsMeta           map[string]metricMeta
	requester             *metricsRequester
	MetricsConfig         []metricsConfig `config:"metrics" validate:"nonzero,required"`
	metadataCacheRegistry *gcp.CacheRegistry
}

// metricsConfig holds a configuration specific for metrics metricset.
type metricsConfig struct {
	ServiceName string `config:"service"  validate:"required"`
	// ServiceMetricPrefix allows to specify the prefix string for MetricTypes
	// Stackdriver requires metrics to be prefixed with a common prefix.
	// This prefix changes based on the services the metrics belongs to.
	ServiceMetricPrefix string   `config:"service_metric_prefix"`
	MetricTypes         []string `config:"metric_types" validate:"required"`
	Aligner             string   `config:"aligner"`
}

// prefix returns the service metric prefix, falling back to the Google Cloud
// monitoring service prefix when not specified.
// The prefix is normalized to always end with '/'.
func (mc metricsConfig) prefix() string {
	prefix := mc.ServiceMetricPrefix

	// NOTE: fallback to Google Cloud prefix for backward compatibility
	// Prefix <service>.googleapis.com/ works only for Google Cloud metrics
	// List: https://cloud.google.com/monitoring/api/metrics_gcp
	if prefix == "" {
		prefix = mc.ServiceName + ".googleapis.com/"
	}

	// Final slash is part of prefix. Creating a prefix with final slash
	// normalize the prefix for other use cases
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}

	return prefix
}

// AddPrefixTo adds the required service metric prefix to the given metric
func (mc metricsConfig) AddPrefixTo(metric string) string {
	return mc.prefix() + metric
}

// RemovePrefixFrom removes service metric prefix from the given metric
func (mc metricsConfig) RemovePrefixFrom(metric string) string {
	return strings.TrimPrefix(metric, mc.prefix())
}

type metricMeta struct {
	samplePeriod time.Duration
	ingestDelay  time.Duration
}

type config struct {
	Zone                       string        `config:"zone"`
	Region                     string        `config:"region"`
	Regions                    []string      `config:"regions"`
	LocationLabel              string        `config:"location_label"`
	ProjectID                  string        `config:"project_id" validate:"required"`
	ExcludeLabels              bool          `config:"exclude_labels"`
	CredentialsFilePath        string        `config:"credentials_file_path"`
	CredentialsJSON            string        `config:"credentials_json"`
	Endpoint                   string        `config:"endpoint"`
	CollectDataprocUserLabels  bool          `config:"collect_dataproc_user_labels"`
	MetadataCache              bool          `config:"metadata_cache"`
	MetadataCacheRefreshPeriod time.Duration `config:"metadata_cache_refresh_period"`

	opt              []option.ClientOption
	period           *durationpb.Duration
	organizationID   string
	organizationName string
	projectName      string
}

// New creates a new instance of the MetricSet. New is responsible for unpacking
// any MetricSet specific configuration options if there are any.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	m := &MetricSet{BaseMetricSet: base}

	if err := base.Module().UnpackConfig(&m.config); err != nil {
		return nil, err
	}

	metricsConfigs := struct {
		Metrics []metricsConfig `config:"metrics" validate:"nonzero,required"`
	}{}

	if err := base.Module().UnpackConfig(&metricsConfigs); err != nil {
		return nil, err
	}

	m.MetricsConfig = metricsConfigs.Metrics

	if m.config.CredentialsFilePath != "" && m.config.CredentialsJSON != "" {
		return m, fmt.Errorf("both credentials_file_path and credentials_json specified, you must use only one of them")
	} else if m.config.CredentialsFilePath != "" {
		m.config.opt = []option.ClientOption{option.WithCredentialsFile(m.config.CredentialsFilePath)}
	} else if m.config.CredentialsJSON != "" {
		m.config.opt = []option.ClientOption{option.WithCredentialsJSON([]byte(m.config.CredentialsJSON))}
	} else {
		return m, fmt.Errorf("no credentials_file_path or credentials_json specified")
	}

	if m.config.Endpoint != "" {
		m.Logger().Warnf("You are using a custom endpoint '%s' for the GCP API calls.", m.config.Endpoint)
		m.config.opt = append(m.config.opt, option.WithEndpoint(m.config.Endpoint))
	}

	m.config.period = &durationpb.Duration{
		Seconds: int64(m.Module().Config().Period.Seconds()),
	}

	if err := validatePeriodForGCP(m.Module().Config().Period); err != nil {
		m.Logger().Warnf("Period has been set to default value of 60s: %s", err)
		m.config.period = &durationpb.Duration{
			Seconds: int64(gcp.MonitoringMetricsSamplingRate),
		}
	}

	// Get ingest delay and sample period for each metric type
	ctx := context.Background()
	// set organization id
	if errs := m.setOrgAndProjectDetails(ctx); errs != nil {
		m.Logger().Warnf("error occurred while fetching organization and project details: %s", errs)
	}
	client, err := monitoring.NewMetricClient(ctx, m.config.opt...)
	if err != nil {
		return nil, fmt.Errorf("error creating Stackdriver client: %w", err)
	}

	m.metricsMeta, err = m.metricDescriptor(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("error calling metricDescriptor function: %w", err)
	}

	m.requester = &metricsRequester{
		config: m.config,
		client: client,
		logger: base.Logger().Named(MetricsetName),
	}

	var metadataCacheRefreshPeriod time.Duration
	if m.config.MetadataCache {
		metadataCacheRefreshPeriod = m.config.MetadataCacheRefreshPeriod
		if metadataCacheRefreshPeriod <= 0 {
			metadataCacheRefreshPeriod = time.Hour // Default to 1 hour if not specified
		}
	} else {
		// Cache is always expired - essentially disabled
		metadataCacheRefreshPeriod = 0
	}

	m.metadataCacheRegistry = gcp.NewCacheRegistry(m.Logger(), metadataCacheRefreshPeriod)

	m.Logger().Warn("extra charges on Google Cloud API requests will be generated by this metricset")
	return m, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(ctx context.Context, reporter mb.ReporterV2) (err error) {
	for _, sdc := range m.MetricsConfig {
		m.Logger().Debugf("metrics config: %v", sdc)
		// m.metricsMeta contains all metrics to be collected, not just the one in the current MetricsConfig.
		// this loop filters the metrics in metricsMeta so requester.Metrics can collect only the appropriate
		// ones.
		// See https://github.com/elastic/beats/pull/29514
		metricsToCollect := map[string]metricMeta{}
		for _, v := range sdc.MetricTypes {
			metricsToCollect[sdc.AddPrefixTo(v)] = m.metricsMeta[sdc.AddPrefixTo(v)]
		}

		// Collect time series values from Google Cloud Monitoring API
		timeSeries, err := m.requester.Metrics(ctx, sdc.ServiceName, sdc.Aligner, metricsToCollect)
		if err != nil {
			err = fmt.Errorf("error trying to get metrics for project '%s' and zone '%s' or region '%s': %w", m.config.ProjectID, m.config.Zone, m.config.Region, err)
			m.Logger().Error(err)
			return err
		}

		events, err := m.mapToEvents(ctx, timeSeries, sdc)
		if err != nil {
			err = fmt.Errorf("mapToEvents failed: %w", err)
			m.Logger().Error(err)
			return err
		}

		// Publish events to Elasticsearch
		m.Logger().Debugf("Total %d of events are created for service name = %s and metric type = %s.", len(events), sdc.ServiceName, sdc.MetricTypes)
		for _, event := range events {
			reporter.Event(event)
		}
	}

	return nil
}

// mapToEvents maps time series data from GCP into events for Elasticsearch.
func (m *MetricSet) mapToEvents(ctx context.Context, timeSeries []timeSeriesWithAligner, sdc metricsConfig) ([]mb.Event, error) {
	mapper := newIncomingFieldMapper(m.Logger(), sdc)

	var metadataService gcp.MetadataService
	var err error

	if !m.config.ExcludeLabels {
		if metadataService, err = NewMetadataServiceForConfig(ctx, m.config, sdc.ServiceName, m.metadataCacheRegistry, m.Logger()); err != nil {
			return nil, fmt.Errorf("error trying to create metadata service: %w", err)
		}
	}

	// Group the time series values by common traits.
	timeSeriesGroups := m.groupTimeSeries(ctx, timeSeries, metadataService, mapper)

	// Create single events for each time series group.
	events := createEventsFromGroups(sdc.ServiceName, timeSeriesGroups)

	return events, nil
}

// validatePeriodForGCP returns nil if the Period in the module config is in the accepted threshold
func validatePeriodForGCP(d time.Duration) (err error) {
	if d.Seconds() < gcp.MonitoringMetricsSamplingRate {
		return fmt.Errorf("period in Google Cloud config file cannot be set to less than %d seconds", gcp.MonitoringMetricsSamplingRate)
	}

	return nil
}

// Validate metrics related config
func (mc *metricsConfig) Validate() error {
	gcpAlignerNames := make([]string, 0)
	for k := range gcp.AlignersMapToGCP {
		gcpAlignerNames = append(gcpAlignerNames, k)
	}

	if mc.Aligner != "" {
		if _, ok := gcp.AlignersMapToGCP[mc.Aligner]; !ok {
			return fmt.Errorf("the given aligner is not supported, please specify one of %s as aligner", gcpAlignerNames)
		}
	}
	return nil
}

// metricDescriptor calls ListMetricDescriptorsRequest API to get metric metadata
// (sample period and ingest delay) of each given metric type
func (m *MetricSet) metricDescriptor(ctx context.Context, client *monitoring.MetricClient) (map[string]metricMeta, error) {
	metricsWithMeta := make(map[string]metricMeta, 0)
	req := &monitoringpb.ListMetricDescriptorsRequest{
		Name: "projects/" + m.config.ProjectID,
	}

	for _, sdc := range m.MetricsConfig {
		for _, mt := range sdc.MetricTypes {
			id := sdc.AddPrefixTo(mt)
			req.Filter = fmt.Sprintf(`metric.type = starts_with("%s")`, id)
			it := client.ListMetricDescriptors(ctx, req)

			for {
				out, err := it.Next()
				if err != nil && !errors.Is(err, iterator.Done) {
					err = fmt.Errorf("could not make ListMetricDescriptors request for metric type %s: %w", mt, err)
					m.Logger().Error(err)
					return metricsWithMeta, err
				}

				if out != nil {
					metricsWithMeta = m.getMetadata(out, metricsWithMeta)
				}

				if errors.Is(err, iterator.Done) {
					break
				}

			}

			// NOTE: if a metric is not added to the metricsWithMeta map is not collected subsequently.
			// Such a case is an error, as the configuration is explicitly requesting a metric that the beat
			// is not able to collect, so we provide a logging statement for this behaviour.
			if _, ok := metricsWithMeta[id]; !ok {
				m.Logger().Errorf("%s metric descriptor is empty, this metric will not be collected", mt)
			}
		}
	}

	return metricsWithMeta, nil
}

func (m *MetricSet) getMetadata(out *metric.MetricDescriptor, metricsWithMeta map[string]metricMeta) map[string]metricMeta {
	// Set samplePeriod default to 60 seconds and ingestDelay default to 0.
	meta := metricMeta{
		samplePeriod: 60 * time.Second,
		ingestDelay:  0 * time.Second,
	}

	if out.Metadata != nil {
		if out.Metadata.SamplePeriod != nil {
			m.Logger().Debugf("For metric type %s: sample period = %s", out.Type, out.Metadata.SamplePeriod)
			meta.samplePeriod = time.Duration(out.Metadata.SamplePeriod.Seconds) * time.Second
		}

		if out.Metadata.IngestDelay != nil {
			m.Logger().Debugf("For metric type %s: ingest delay = %s", out.Type, out.Metadata.IngestDelay)
			meta.ingestDelay = time.Duration(out.Metadata.IngestDelay.Seconds) * time.Second
		}
	}

	metricsWithMeta[out.Type] = meta
	return metricsWithMeta
}

func addHostFields(groupedEvents []KeyValuePoint) mapstr.M {
	hostRootFields := groupedEvents[0].ECS
	// add host.id and host.name
	if hostID, err := groupedEvents[0].ECS.GetValue("cloud.instance.id"); err == nil {
		_, _ = hostRootFields.Put("host.id", hostID)
	}

	if hostName, err := groupedEvents[0].ECS.GetValue("cloud.instance.name"); err == nil {
		_, _ = hostRootFields.Put("host.name", hostName)
	}

	hostFieldTable := map[string]string{
		"instance.cpu.utilization.value":                "host.cpu.usage",
		"instance.network.sent_bytes_count.value":       "host.network.ingress.bytes",
		"instance.network.received_bytes_count.value":   "host.network.egress.bytes",
		"instance.network.sent_packets_count.value":     "host.network.ingress.packets",
		"instance.network.received_packets_count.value": "host.network.egress.packets",
		"instance.disk.read_bytes_count.value":          "host.disk.read.bytes",
		"instance.disk.write_bytes_count.value":         "host.disk.write.bytes",
	}

	for _, singleEvent := range groupedEvents {
		if hostMetricName, ok := hostFieldTable[singleEvent.Key]; ok {
			_, _ = hostRootFields.Put(hostMetricName, singleEvent.Value)
		}
	}
	return hostRootFields
}

func (m *MetricSet) setOrgAndProjectDetails(ctx context.Context) []error {
	var errs []error

	// Initialize the Cloud Resource Manager service
	srv, err := cloudresourcemanager.NewService(ctx, m.config.opt...)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to create cloudresourcemanager service: %w", err))
		return errs
	}
	// Set Project name
	err = m.setProjectDetails(ctx, srv)
	if err != nil {
		errs = append(errs, err)
	}
	//Set Organization Details
	err = m.setOrganizationDetails(ctx, srv)
	if err != nil {
		errs = append(errs, err)
	}
	return errs
}

func (m *MetricSet) setProjectDetails(ctx context.Context, service *cloudresourcemanager.Service) error {
	project, err := service.Projects.Get(m.config.ProjectID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get project name: %w", err)
	}
	if project != nil {
		m.config.projectName = project.Name
	}
	return nil
}

func (m *MetricSet) setOrganizationDetails(ctx context.Context, service *cloudresourcemanager.Service) error {
	// Get the project ancestor details
	ancestryResponse, err := service.Projects.GetAncestry(m.config.ProjectID, &cloudresourcemanager.GetAncestryRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get project ancestors: %w", err)
	}
	if len(ancestryResponse.Ancestor) == 0 {
		return fmt.Errorf("no ancestors found for project '%s'", m.config.ProjectID)
	}
	ancestor := ancestryResponse.Ancestor[len(ancestryResponse.Ancestor)-1]

	if ancestor.ResourceId.Type == "organization" {
		m.config.organizationID = ancestor.ResourceId.Id
		orgReq := service.Organizations.Get(fmt.Sprintf("organizations/%s", m.config.organizationID))

		orgDetails, err := orgReq.Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to get organization details: %w", err)
		}

		m.config.organizationName = orgDetails.DisplayName
	}
	return nil
}
