package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/goark/errs"

	"github.com/goark/fetch"
	"github.com/goark/gpgpdump/ecode"
)

const maxKeys = 100

var maxKeysStr = strconv.Itoa(maxKeys)

//Get returns OpenPGP ASCII armor text from GitHub user profile
func Get(ctx context.Context, cli fetch.Client, username string) ([]byte, error) {
	resp, err := cli.Get(makeURL(username), fetch.WithContext(ctx))
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("username", username))
	}
	b, err := resp.DumpBodyAndClose()
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("username", username))
	}
	return b, nil
}

func makeURL(username string) *url.URL {
	u, _ := fetch.URL(fmt.Sprintf("https://github.com/%s.gpg", username))
	return u
}

//GetKey returns JSON text for GitHub OpenPGP API
func GetKey(ctx context.Context, cli fetch.Client, username string, keyID string) ([]byte, error) {
	if len(keyID) == 0 {
		return Get(ctx, cli, username)
	}
	for i := 1; ; i++ {
		keys, err := getInPage(ctx, cli, username, i)
		if err != nil {
			return nil, errs.Wrap(err, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
		}
		for _, k := range keys {
			if strings.EqualFold(k.KeyID, strings.TrimPrefix(strings.ToLower(keyID), "0x")) {
				if k.RawKey == nil {
					return nil, errs.Wrap(ecode.ErrNoKey, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
				}
				return []byte(*k.RawKey), nil
			}
		}
		if len(keys) < maxKeys {
			break
		}
	}
	return nil, errs.Wrap(ecode.ErrNoKey, errs.WithContext("username", username), errs.WithContext("keyID", keyID))
}

func getInPage(ctx context.Context, cli fetch.Client, username string, page int) ([]*OpenPGPKey, error) {
	u, err := makeURLAPI(username, page)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("username", username), errs.WithContext("page", page))
	}
	resp, err := cli.Get(
		u,
		fetch.WithContext(ctx),
		fetch.WithRequestHeaderSet("Accept", "application/vnd.github.v3+json"),
	)
	if err != nil {
		return nil, errs.Wrap(ecode.ErrInvalidRequest, errs.WithCause(err), errs.WithContext("username", username), errs.WithContext("page", page))
	}
	defer resp.Close()

	var keys []*OpenPGPKey
	if err := json.NewDecoder(resp.Body()).Decode(&keys); err != nil {
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

/* Copyright 2020-2021 Spiegel
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
