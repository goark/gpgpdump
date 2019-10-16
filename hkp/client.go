package hkp

import (
	"bufio"
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
)

//Client is http.Client for HKP
type Client struct {
	client *http.Client
	server *Server
	ctx    context.Context
}

//Get returns result of HKP get command
func (c *Client) Get(userID string) ([]byte, error) {
	values := url.Values{
		"search": {userID},
		"op":     {"get"},
	}
	u := c.server.URL()
	u.Path = "/pks/lookup"
	u.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(c.ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, errs.Wrap(err, "", errs.WithContext("url", u.String()))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errs.Wrap(err, "", errs.WithContext("url", u.String()))
	}
	defer resp.Body.Close()

	if !(resp.StatusCode != 0 && resp.StatusCode < http.StatusBadRequest) {
		return nil, errs.Wrap(ecode.ErrHTTPStatus, "", errs.WithContext("url", u.String()), errs.WithContext("status", resp.Status))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Wrap(err, "", errs.WithContext("url", u.String()))
	}
	return body, errs.Wrap(hasASCIIArmorText(body), "", errs.WithContext("url", u.String()))
}

func hasASCIIArmorText(body []byte) error {
	r := bytes.NewReader(body)
	armorFlag := false
	scn := bufio.NewScanner(r)
	for scn.Scan() {
		if strings.HasPrefix(scn.Text(), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
			armorFlag = true
			break
		}
	}
	if err := scn.Err(); err != nil {
		return err
	}
	if !armorFlag {
		return ecode.ErrArmorText
	}
	return nil
}

/* Copyright 2019 Spiegel
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
