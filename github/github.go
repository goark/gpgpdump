package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/armtext"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
	"github.com/spiegel-im-spiegel/gpgpdump/fetch"
)

const maxKeys = 100

var maxKeysStr = strconv.Itoa(maxKeys)

//Get returns OpenPGP ASCII armor text from GitHub user profile
func Get(cli fetch.Client, username string) ([]byte, error) {
	r, err := cli.Get(makeURL(username))
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("username", username))
	}
	defer r.Close()

	buf, err := armtext.Get(r)
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("username", username))
	}
	return buf.Bytes(), nil
}

func makeURL(username string) string {
	return fmt.Sprintf("https://github.com/%s.gpg", username)
}

//GetKey returns JSON text for GitHub OpenPGP API
func GetKey(cli fetch.Client, username string, keyID string) ([]byte, error) {
	if len(keyID) == 0 {
		return Get(cli, username)
	}
	for i := 1; ; i++ {
		keys, err := getInPage(cli, username, i)
		if err != nil {
			return nil, errs.Wrap(err, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
		}
		for _, k := range keys {
			if strings.EqualFold(k.KeyID, strings.TrimPrefix(strings.ToLower(keyID), "0x")) {
				if k.RawKey == nil {
					return nil, errs.Wrap(ecode.ErrNoKey, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
				}
				buf, err := armtext.Get(strings.NewReader(*k.RawKey))
				if err != nil {
					return nil, errs.Wrap(ecode.ErrNoKey, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
				}
				return buf.Bytes(), nil
			}
		}
		if len(keys) < maxKeys {
			break
		}
	}
	return nil, errs.Wrap(ecode.ErrNoKey, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
}

func getInPage(cli fetch.Client, username string, page int) ([]*OpenPGPKey, error) {
	u, err := makeURLAPI(username, page)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("username", username), errs.WithContext("page", page))
	}
	req, err := cli.Request(http.MethodGet, u)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("url", u.String()))
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	r, err := cli.Fetch(req)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("url", u.String()))
	}
	defer r.Close()

	var keys []*OpenPGPKey
	if err := json.NewDecoder(r).Decode(&keys); err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("url", u.String()))
	}
	return keys, nil
}

func makeURLAPI(username string, page int) (*url.URL, error) {
	if page < 1 {
		page = 1
	}
	u, err := url.Parse(fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", username))
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("username", username), errs.WithContext("page", page))
	}
	q := u.Query()
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", maxKeysStr)
	u.RawQuery = q.Encode()
	return u, nil
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
