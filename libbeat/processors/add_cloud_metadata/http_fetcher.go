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

package add_cloud_metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	cfg "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

type httpMetadataFetcher struct {
	provider         string
	headers          map[string]string
	responseHandlers map[string]responseHandler
	conv             schemaConv
}

// responseHandler is the callback function that used to write something
// to the result according the HTTP response.
type responseHandler func(all []byte, res *result) error

type schemaConv func(m map[string]interface{}) mapstr.M

// newMetadataFetcher return metadataFetcher with one pass JSON responseHandler.
func newMetadataFetcher(
	c *cfg.C,
	provider string,
	headers map[string]string,
	host string,
	conv schemaConv,
	uri string,
) (*httpMetadataFetcher, error) {
	urls, err := getMetadataURLs(c, host, []string{uri})
	if err != nil {
		return nil, err
	}
	responseHandlers := map[string]responseHandler{urls[0]: makeJSONPicker(provider)}
	fetcher := &httpMetadataFetcher{provider, headers, responseHandlers, conv}
	return fetcher, nil
}

// fetchMetadata queries metadata from a hosting provider's metadata service.
// Some providers require multiple HTTP requests to gather the whole metadata,
// len(f.responseHandlers)  > 1 indicates that multiple requests are needed.
func (f *httpMetadataFetcher) fetchMetadata(ctx context.Context, client http.Client, _ *logp.Logger) result {
	res := result{provider: f.provider, metadata: mapstr.M{}}
	for url, responseHandler := range f.responseHandlers {
		f.fetchRaw(ctx, client, url, responseHandler, &res)
		if res.err != nil {
			return res
		}
	}

	// Apply schema.
	res.metadata = f.conv(res.metadata)
	res.metadata.Put("cloud.provider", f.provider)

	return res
}

// fetchRaw queries raw metadata from a hosting provider's metadata service.
func (f *httpMetadataFetcher) fetchRaw(
	ctx context.Context,
	client http.Client,
	url string,
	responseHandler responseHandler,
	result *result,
) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.err = fmt.Errorf("failed to create http request for %v: %w", f.provider, err)
		return
	}
	for k, v := range f.headers {
		req.Header.Add(k, v)
	}
	req = req.WithContext(ctx)

	rsp, err := client.Do(req)
	if err != nil {
		result.err = fmt.Errorf("failed requesting %v metadata: %w", f.provider, err)
		return
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		result.err = fmt.Errorf("failed with http status code %v", rsp.StatusCode)
		return
	}

	all, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		result.err = fmt.Errorf("failed requesting %v metadata: %w", f.provider, err)
		return
	}

	// Decode JSON.
	err = responseHandler(all, result)
	if err != nil {
		result.err = err
		return
	}

	return
}

// getMetadataURLs loads config and generates the metadata URLs.
func getMetadataURLs(c *cfg.C, defaultHost string, metadataURIs []string) ([]string, error) {
	return getMetadataURLsWithScheme(c, "http", defaultHost, metadataURIs)
}

// getMetadataURLsWithScheme loads config and generates the metadata URLs.
func getMetadataURLsWithScheme(c *cfg.C, scheme string, defaultHost string, metadataURIs []string) ([]string, error) {
	var urls []string
	config := struct {
		MetadataHostAndPort string            `config:"host"` // Specifies the host and port of the metadata service (for testing purposes only).
		TLSConfig           *tlscommon.Config `config:"ssl"`
	}{
		MetadataHostAndPort: defaultHost,
	}
	err := c.Unpack(&config)
	if err != nil {
		return urls, fmt.Errorf("failed to unpack add_cloud_metadata config: %w", err)
	}
	for _, uri := range metadataURIs {
		urls = append(urls, scheme+"://"+config.MetadataHostAndPort+uri)
	}
	return urls, nil
}

// makeJSONPicker returns a responseHandler function that unmarshals JSON
// from a hosting provider's HTTP response and writes it to the result.
func makeJSONPicker(provider string) responseHandler {
	return func(all []byte, res *result) error {
		dec := json.NewDecoder(bytes.NewReader(all))
		dec.UseNumber()
		err := dec.Decode(&res.metadata)
		if err != nil {
			err = fmt.Errorf("failed to unmarshal %v JSON of '%v': %w", provider, string(all), err)
			return err
		}
		return nil
	}
}
