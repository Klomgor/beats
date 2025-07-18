// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package add_observer_metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/beat"
	cfg "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestConfigDefault(t *testing.T) {
	event := &beat.Event{
		Fields:    mapstr.M{},
		Timestamp: time.Now(),
	}
	testConfig, err := cfg.NewConfigFrom(map[string]interface{}{})
	assert.NoError(t, err)

	p, err := New(testConfig, logptest.NewTestingLogger(t, ""))

	newEvent, err := p.Run(event)
	assert.NoError(t, err)

	v, err := newEvent.GetValue("observer.ip")
	assert.NoError(t, err)
	assert.NotNil(t, v)

	v, err = newEvent.GetValue("observer.mac")
	assert.NoError(t, err)
	assert.NotNil(t, v)
}

func TestOverwriteFalse(t *testing.T) {
	event := &beat.Event{
		Fields:    mapstr.M{"observer": mapstr.M{"foo": "bar"}},
		Timestamp: time.Now(),
	}
	testConfig, err := cfg.NewConfigFrom(map[string]interface{}{})
	require.NoError(t, err)

	p, err := New(testConfig, logptest.NewTestingLogger(t, ""))

	newEvent, err := p.Run(event)
	require.NoError(t, err)

	v, err := newEvent.GetValue("observer")
	require.NoError(t, err)
	assert.Equal(t, mapstr.M{"foo": "bar"}, v)
}

func TestOverwriteTrue(t *testing.T) {
	event := &beat.Event{
		Fields:    mapstr.M{"observer": mapstr.M{"foo": "bar"}},
		Timestamp: time.Now(),
	}
	testConfig, err := cfg.NewConfigFrom(map[string]interface{}{"overwrite": true})
	require.NoError(t, err)

	p, err := New(testConfig, logptest.NewTestingLogger(t, ""))

	newEvent, err := p.Run(event)
	require.NoError(t, err)

	v, err := newEvent.GetValue("observer.hostname")
	require.NoError(t, err)
	assert.NotNil(t, v)
}

func TestConfigNetInfoDisabled(t *testing.T) {
	event := &beat.Event{
		Fields:    mapstr.M{},
		Timestamp: time.Now(),
	}
	testConfig, err := cfg.NewConfigFrom(map[string]interface{}{
		"netinfo.enabled": false,
	})
	assert.NoError(t, err)

	p, err := New(testConfig, logptest.NewTestingLogger(t, ""))

	newEvent, err := p.Run(event)
	assert.NoError(t, err)

	v, err := newEvent.GetValue("observer.ip")
	assert.Error(t, err)
	assert.Nil(t, v)

	v, err = newEvent.GetValue("observer.mac")
	assert.Error(t, err)
	assert.Nil(t, v)
}

func TestConfigGeoEnabled(t *testing.T) {
	event := &beat.Event{
		Fields:    mapstr.M{},
		Timestamp: time.Now(),
	}

	config := map[string]interface{}{
		"geo.name":             "yerevan-am",
		"geo.location":         "40.177200, 44.503490",
		"geo.continent_name":   "Asia",
		"geo.country_name":     "Armenia",
		"geo.country_iso_code": "AM",
		"geo.region_name":      "Erevan",
		"geo.region_iso_code":  "AM-ER",
		"geo.city_name":        "Yerevan",
	}

	testConfig, err := cfg.NewConfigFrom(config)
	assert.NoError(t, err)

	p, err := New(testConfig, logptest.NewTestingLogger(t, ""))
	require.NoError(t, err)

	newEvent, err := p.Run(event)
	assert.NoError(t, err)

	eventGeoField, err := newEvent.GetValue("observer.geo")
	require.NoError(t, err)

	assert.Len(t, eventGeoField, len(config))
}

func TestConfigGeoDisabled(t *testing.T) {
	event := &beat.Event{
		Fields:    mapstr.M{},
		Timestamp: time.Now(),
	}

	config := map[string]interface{}{}

	testConfig, err := cfg.NewConfigFrom(config)
	require.NoError(t, err)

	p, err := New(testConfig, logptest.NewTestingLogger(t, ""))
	require.NoError(t, err)

	newEvent, err := p.Run(event)
	require.NoError(t, err)

	eventGeoField, err := newEvent.GetValue("observer.geo")
	assert.Error(t, err)
	assert.Equal(t, nil, eventGeoField)
}
