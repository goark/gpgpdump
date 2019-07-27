package hkp

import (
	"bufio"
	"bytes"
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
}

//Get returns result of HKP get command
func (c *Client) Get(userID string) ([]byte, error) {
	values := url.Values{
		"search": {userID},
		"op":     {"get"},
	}
	url := c.server.String() + "/pks/lookup?" + values.Encode()
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, errs.Wrapf(err, "error in hkp.Client.Get(\"%v\")", url)
	}
	defer resp.Body.Close()

	if !(resp.StatusCode != 0 && resp.StatusCode < http.StatusBadRequest) {
		return nil, errs.Wrapf(ecode.ErrHTTPStatus, "%v (in %v)", resp.Status, url)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Wrapf(err, "error in hkp.Client.Get(\"%v\")", url)
	}
	return body, errs.Wrapf(hasASCIIArmorText(body), "error in hkp.Client.Get(\"%v\")", url)
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
