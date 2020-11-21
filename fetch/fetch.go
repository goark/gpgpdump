package fetch

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
)

type Client interface {
	Get(string) (io.ReadCloser, error)
	Request(method string, u *url.URL) (*http.Request, error)
	Fetch(*http.Request) (io.ReadCloser, error)
}

//client is class object for HTTP client
type client struct {
	ctx    context.Context
	client *http.Client
}

//Options is self-referential function for functional options pattern
type Options func(*client)

//New function returns Client instance.
func New(opts ...Options) Client {
	cli := &client{ctx: context.Background(), client: http.DefaultClient}
	for _, opt := range opts {
		opt(cli)
	}
	return cli
}

//WithProtocol returns function for setting Reader
func WithContext(ctx context.Context) Options {
	return func(c *client) {
		c.ctx = ctx
	}
}

//WithProtocol returns function for setting Reader
func WithHttpClient(cli *http.Client) Options {
	return func(c *client) {
		c.client = cli
	}
}

//Get method returns respons data from URL.
func (c *client) Get(urlStr string) (io.ReadCloser, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("url", urlStr))
	}
	req, err := c.Request(http.MethodGet, u)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("url", u.String()))
	}
	r, err := c.Fetch(req)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("url", u.String()))
	}
	return r, nil
}

func (c *client) Request(method string, u *url.URL) (*http.Request, error) {
	if c == nil {
		c = New().(*client)
	}
	return http.NewRequestWithContext(c.ctx, method, u.String(), nil)
}

//Fetch method returns respons data from URL.
func (c *client) Fetch(request *http.Request) (io.ReadCloser, error) {
	if c == nil {
		c = New().(*client)
	}
	resp, err := c.client.Do(request)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err))
	}
	if !(resp.StatusCode != 0 && resp.StatusCode < http.StatusBadRequest) {
		resp.Body.Close()
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err))
	}
	return resp.Body, nil
}

/* Copyright 2020 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
