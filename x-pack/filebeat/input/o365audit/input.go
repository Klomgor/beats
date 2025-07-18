// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package o365audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest"

	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	cursor "github.com/elastic/beats/v7/filebeat/input/v2/input-cursor"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/feature"
	"github.com/elastic/beats/v7/libbeat/management/status"
	"github.com/elastic/beats/v7/libbeat/statestore"
	"github.com/elastic/beats/v7/libbeat/version"
	"github.com/elastic/beats/v7/x-pack/filebeat/input/o365audit/poll"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/useragent"
	"github.com/elastic/go-concert/ctxtool"
	"github.com/elastic/go-concert/timed"
)

const (
	pluginName   = "o365audit"
	fieldsPrefix = pluginName
)

type o365input struct {
	config Config
}

// Stream represents an event stream.
type stream struct {
	tenantID    string
	contentType string
}

func Plugin(log *logp.Logger, store statestore.States) v2.Plugin {
	return v2.Plugin{
		Name:       pluginName,
		Stability:  feature.Experimental,
		Deprecated: true,
		Info:       "O365 logs",
		Doc:        "Collect logs from O365 service",
		Manager: &cursor.InputManager{
			Logger:     log,
			StateStore: store,
			Type:       pluginName,
			Configure:  configure,
		},

		// ExcludeFromFIPS = true to prevent this input from being used in FIPS-capable
		// Filebeat distributions.  This input indirectly uses algorithms that are not
		// FIPS-compliant. Specifically, the input depends on the
		// github.com/Azure/azure-sdk-for-go/sdk/azidentity package which, in turn,
		// depends on the golang.org/x/crypto/pkcs12 package, which is not FIPS-compliant.
		ExcludeFromFIPS: true,
	}
}

func configure(cfg *conf.C, _ *logp.Logger) ([]cursor.Source, cursor.Input, error) {
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return nil, nil, fmt.Errorf("reading config: %w", err)
	}

	var sources []cursor.Source
	for _, tenantID := range config.TenantID {
		for _, contentType := range config.ContentType {
			sources = append(sources, &stream{
				tenantID:    tenantID,
				contentType: contentType,
			})
		}
	}

	return sources, &o365input{config: config}, nil
}

func (s *stream) Name() string {
	return s.tenantID + "::" + s.contentType
}

func (inp *o365input) Name() string { return pluginName }

func (inp *o365input) Test(src cursor.Source, ctx v2.TestContext) error {
	tenantID := src.(*stream).tenantID
	auth, err := inp.config.NewTokenProvider(tenantID)
	if err != nil {
		return err
	}

	if _, err := auth.Token(ctxtool.FromCanceller(ctx.Cancelation)); err != nil {
		return fmt.Errorf("unable to acquire authentication token for tenant:%s: %w", tenantID, err)
	}

	return nil
}

func (inp *o365input) Run(ctx v2.Context, src cursor.Source, cursor cursor.Cursor, pub cursor.Publisher) error {
	stat := ctx.StatusReporter
	if stat == nil {
		stat = noopReporter{}
	}
	stat.UpdateStatus(status.Starting, "")

	stream, ok := src.(*stream)
	if !ok {
		// This should never happen.
		stat.UpdateStatus(status.Failed, "source is not an O365 stream")
		return errors.New("source is not an O365 stream")
	}

	for ctx.Cancelation.Err() == nil {
		err := inp.run(ctx, stream, cursor, pub, stat)
		switch {
		case err == nil, errors.Is(err, context.Canceled):
			return nil
		case err != ctx.Cancelation.Err():
			msg := mapstr.M{}
			msg.Put("error.message", err.Error())
			msg.Put("event.kind", "pipeline_error")
			event := beat.Event{
				Timestamp: time.Now(),
				Fields:    msg,
			}
			if err := pub.Publish(event, nil); err != nil {
				stat.UpdateStatus(status.Degraded, "failed to publish error: "+err.Error())
				ctx.Logger.Errorf("publisher.Publish failed: %v", err)
			}
			stat.UpdateStatus(status.Degraded, err.Error())
			ctx.Logger.Errorf("Input failed: %v", err)
			ctx.Logger.Infof("Restarting in %v", inp.config.API.ErrorRetryInterval)
			timed.Wait(ctx.Cancelation, inp.config.API.ErrorRetryInterval)
		}
	}

	return nil
}

func (inp *o365input) run(v2ctx v2.Context, stream *stream, cursor cursor.Cursor, pub cursor.Publisher, stat status.StatusReporter) error {
	tenantID, contentType := stream.tenantID, stream.contentType
	log := v2ctx.Logger.With("tenantID", tenantID, "contentType", contentType)
	ctx := ctxtool.FromCanceller(v2ctx.Cancelation)

	tokenProvider, err := inp.config.NewTokenProvider(stream.tenantID)
	if err != nil {
		return err
	}

	if _, err := tokenProvider.Token(ctx); err != nil {
		return fmt.Errorf("unable to acquire authentication token for tenant:%s: %w", stream.tenantID, err)
	}

	config := &inp.config

	// MaxRequestsPerMinute limitation is per tenant.
	delay := time.Duration(len(config.ContentType)) * time.Minute / time.Duration(config.API.MaxRequestsPerMinute)

	poller, err := poll.New(
		poll.WithTokenProvider(tokenProvider),
		poll.WithMinRequestInterval(delay),
		poll.WithLogger(log),
		poll.WithContext(ctx),
		poll.WithRequestDecorator(
			autorest.WithUserAgent(useragent.UserAgent("Filebeat-"+pluginName, version.GetDefaultVersion(), version.Commit(), version.BuildTime().String())),
			autorest.WithQueryParameters(mapstr.M{
				"publisherIdentifier": tenantID,
			}),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create API poller: %w", err)
	}

	start := initCheckpoint(log, cursor, config.API.MaxRetention)
	action := makeListBlob(start, apiEnvironment{
		logger:      log,
		status:      stat,
		tenantID:    tenantID,
		contentType: contentType,
		config:      inp.config.API,
		callback:    pub.Publish,
		clock:       time.Now,
	})
	if start.Line > 0 {
		action = action.WithStartTime(start.StartTime)
	}

	log.Infow("Start fetching events", "cursor", start)
	return poller.Run(action)
}

func initCheckpoint(log *logp.Logger, c cursor.Cursor, maxRetention time.Duration) checkpoint {
	var cp checkpoint
	retentionLimit := time.Now().UTC().Add(-maxRetention)

	if c.IsNew() {
		log.Infof("No saved state found. Will fetch events for the last %v.", maxRetention.String())
		cp.Timestamp = retentionLimit
	} else {
		err := c.Unpack(&cp)
		if err != nil {
			log.Errorw("Error loading saved state. Will fetch all retained events. "+
				"Depending on max_retention, this can cause event loss or duplication.",
				"error", err,
				"max_retention", maxRetention.String())
			cp.Timestamp = retentionLimit
		}
	}

	if cp.Timestamp.Before(retentionLimit) {
		log.Warnw("Last update exceeds the retention limit. "+
			"Probably some events have been lost.",
			"resume_since", cp,
			"retention_limit", retentionLimit,
			"max_retention", maxRetention.String())
		// Due to API limitations, it's necessary to perform a query for each
		// day. These avoids performing a lot of queries that will return empty
		// when the input hasn't run in a long time.
		cp.Timestamp = retentionLimit
	}

	return cp
}

type apiEnvironment struct {
	tenantID    string
	contentType string
	config      APIConfig
	callback    func(event beat.Event, cursor interface{}) error
	status      status.StatusReporter
	logger      *logp.Logger
	clock       func() time.Time
}

// Report returns an action that produces a beat.Event from the given object.
func (env apiEnvironment) Report(raw json.RawMessage, doc mapstr.M, private interface{}) poll.Action {
	return func(poll.Enqueuer) error {
		err := env.callback(env.toBeatEvent(raw, doc), private)
		switch err {
		case nil:
			env.status.UpdateStatus(status.Running, "")
		default:
			env.status.UpdateStatus(status.Degraded, "failed to publish event: "+err.Error())
		}
		return err
	}
}

// ReportAPIError returns an action that produces a beat.Event from an API error.
func (env apiEnvironment) ReportAPIError(err apiError) poll.Action {
	return func(poll.Enqueuer) error {
		msg := err.Error.Message
		err := env.callback(err.toBeatEvent(), nil)
		if err != nil {
			env.status.UpdateStatus(status.Degraded, fmt.Sprintf("failed to publish API error event %q: %v", msg, err.Error()))
		}
		return err
	}
}

func (env apiEnvironment) toBeatEvent(raw json.RawMessage, doc mapstr.M) beat.Event {
	var errs []error
	ts, err := getDateKey(doc, "CreationTime", apiDateFormats)
	if err != nil {
		ts = time.Now()
		errs = append(errs, fmt.Errorf("failed parsing CreationTime: %w", err))
	}
	b := beat.Event{
		Timestamp: ts,
		Fields: mapstr.M{
			fieldsPrefix: doc,
		},
	}
	if env.config.SetIDFromAuditRecord {
		if id, err := getString(doc, "Id"); err == nil && len(id) > 0 {
			b.SetID(id)
		}
	}
	if env.config.PreserveOriginalEvent {
		//nolint:errcheck // ignore
		b.PutValue("event.original", string(raw))
	}
	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for idx, e := range errs {
			msgs[idx] = e.Error()
		}
		//nolint:errcheck // ignore
		b.PutValue("error.message", msgs)
	}
	return b
}

type noopReporter struct{}

func (noopReporter) UpdateStatus(status.Status, string) {}
