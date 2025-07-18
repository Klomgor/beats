// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package cluster_settings

import (
	"testing"

	"github.com/elastic/beats/v7/x-pack/metricbeat/module/autoops_es/auto_ops_testing"
	autoopsevents "github.com/elastic/beats/v7/x-pack/metricbeat/module/autoops_es/events"

	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/x-pack/metricbeat/module/autoops_es/metricset"
)

var (
	setupClusterSettingsErrorServer = auto_ops_testing.SetupDataErrorServer(ClusterSettingsPath)
	setupSuccessfulServer           = auto_ops_testing.SetupSuccessfulServer(ClusterSettingsPath)
	useNamedMetricSet               = auto_ops_testing.UseNamedMetricSet(ClusterSettingsMetricSet)
)

func TestSuccessfulFetch(t *testing.T) {
	metricset.RunTestsForFetcherWithGlobFiles(t, "./_meta/test/cluster_settings.*.json", setupSuccessfulServer, useNamedMetricSet, func(t *testing.T, data metricset.FetcherData[map[string]interface{}]) {
		require.NoError(t, data.Error)

		require.Equal(t, 1, len(data.Reporter.GetEvents()))
	})
}

func TestFailedClusterInfoFetch(t *testing.T) {
	metricset.RunTestsForFetcherWithGlobFiles(t, "./_meta/test/cluster_settings.*.json", auto_ops_testing.SetupClusterInfoErrorServer, useNamedMetricSet, func(t *testing.T, data metricset.FetcherData[map[string]interface{}]) {
		require.ErrorContains(t, data.Error, "failed to get cluster info from cluster, cluster_settings metricset")
	})
}

func TestFailedClusterSettingsFetch(t *testing.T) {
	metricset.RunTestsForFetcherWithGlobFiles(t, "./_meta/test/cluster_settings.*.json", setupClusterSettingsErrorServer, useNamedMetricSet, func(t *testing.T, data metricset.FetcherData[map[string]interface{}]) {
		require.ErrorContains(t, data.Error, "failed to get data, cluster_settings metricset")
	})
}

func TestFailedClusterSettingsFetchEventsMapping(t *testing.T) {
	metricset.RunTestsForFetcherWithGlobFiles(t, "./_meta/test/no_*.cluster_settings.*.json", setupSuccessfulServer, useNamedMetricSet, func(t *testing.T, data metricset.FetcherData[map[string]interface{}]) {
		require.Error(t, data.Error)
		require.Equal(t, 1, len(data.Reporter.GetEvents()))

		// Check error event
		event := data.Reporter.GetEvents()[0]
		_, ok := event.MetricSetFields["error"].(autoopsevents.ErrorEvent)
		require.True(t, ok, "error field should be of type error.ErrorEvent")
	})
}
