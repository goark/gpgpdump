package github_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/spiegel-im-spiegel/fetch"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
	"github.com/spiegel-im-spiegel/gpgpdump/github"
)

var (
	inputText1 = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: sks.pod02.fleetstreetops.com

mQENBEr24dcBCADQeCxUo1pNF33ytHuzLn4vK9Z8LWXCUoZsQAZ9+cMKAzbQ9ncO+LfMleDz
RpjsBxYWDaTnn6a8OySveDcw9/CZ9Wu0ND0+uHErdNk5qh+z81x15sOAfN9xj4pUm0iH092Z
wuILrLjWWqgKMZYmB8HKaHXDkQmSfQmhx7oyZ4tWHfMN/VqBWLyUt0RaU0X+s4zLrdJSsTaf
ECZRo/2OJecpyBzLBc45Tzv3RJAXTyv31MLDYn38bS0EiShRoqaGIZthC7ZnX9EoaS2trg1K
uZtv6NeScRU4TqS21q/kYnE6HBnAMg7mI7dtFbg8x20TB2rTA5v8o/8cqZ3MLQukqjZ1ABEB
AAG0GUFsaWNlIDxhbGljZUBleGFtcGxlLmNvbT6IjAQQFggANBYhBDvMx8/SWX5TRN2WSnKb
Uj0R86jXBQJe8BASFhSAAAAAAA0AAHJlbUBnbnVwZy5vcmcACgkQcptSPRHzqNexFQEA3wFC
8PN9jOyFJak06/OWplZpQCMvBEBKJl+hJZYLNdIBAPEZay004L/HD0CA6O8l9emQyDCglYkT
y2AIzzpeFvABiQE4BBMBAgAiBQJK9uHXAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAK
CRBEzmkA4rMHpJNiB/0bWxus4CYj1fdRmRTIJmSVNiuqrohX3c1DZry8j34v5fEFLsAwHPL8
54uw2FhQVgjhZN75vKPzghsZoUh7dbtC+KZuACnAqmsHV/Nx9D0Ac7x8tVEvt90glG9jkp8Q
SMLA8SElUmfPQoXvjugc93ZdZs7A6J8Nxxlcu9zsrKQqH+60aTIUs03F5D/PaQFeZOCFkoOt
dj5QTV8Kwkow4nnMdQ55dJCnD1Ze7RFZmMEqd+jAQ6N3Vg41f6+qsmBew+t7aqC30tWpVw+s
6XSdIkbFfLN8yPiRARn1r8U2ZzsLDs1O6ftdcBNaQTOnl/4zXNu+R1skFwWfDML/xkcW3pVx
uQENBEr24dcBCADZ+26/F9bLQ92XPiCeCwPG2rwzg2o4a5kHkpX9lR6HLwDKbHpXZIjyEIFR
eu1oefIGPmnlpdVuCh8ulaE7574vU3fEg6B/QoSTVz6mAKeLuMjx0qth02Gots/U/sixx/Nn
V5epDVuR/exH6egunpzDvEg+UD6Rkib86LIL8CmQXq38ZZVfd/Px0rObF7YyUbWUidqKW6+l
2lj/X6svQdx3B65PWGwBuoxv3j4eLP7zJouyGf7h+2H9v3eIcPTyTOgiT50YwztdalMFllkP
71Lf3F/6L5zo4yZ4/YMyCkHV+2LevwjnDpjGSHyXQ603WPjQtOwybcgCkV0N+KuYwvinABEB
AAGJAR8EGAECAAkFAkr24dcCGwwACgkQRM5pAOKzB6Rm8wgAyw09KTy98Y1lMvuS4sr+IHPt
RCLg8/JKHfNut8N+W7z9B+7q1bB9XDg1KxtYhuEtwVr393xfY8v9f1saUUt4bh8hwrciU5gt
cGP7MhgQT5xztAkM1JChtT2+SKRF4NU9El4oUao4lbTU/jB8ZSF2jJAhUnpcHgCSzPzsqyye
XMGK/CQPmGRWr96c9L2efBZvV0aLrziI/ftIl+TJ68P9oV0RwjoA6z6dWgwMfaZ8GN6MsuXQ
KH/KNBqYms9+E0UXWd70hQZaKKV3Tch/ldnAVMSwMaKmkD6zFvULJqkcP+QNWIqxLqc7He8/
P1FRChSHTwsazDVjP0AKzttqhGYxNw==
=QFnp
-----END PGP PUBLIC KEY BLOCK-----
`
	inputText2 = `[
  {
    "id": 1070011,
    "primary_key_id": null,
    "key_id": "3B460BA9A59048C9",
    "raw_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nmDMEX5e8IxYJKwYBBAHaRw8BAQdAsbKSTsqzMQSUdWv/UQBfYf+HD9/+dzCT+zVN\r\nIvZRQ/e0L1NwaWVnZWwgKGdpdGh1YikgPHNwaWVnZWwuaW0uc3BpZWdlbEBnbWFp\r\nbC5jb20+iJAEExYIADgWIQRK8EwUs6FchRaOGmc7RguppZBIyQUCX5e8IwIbAwUL\r\nCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRA7RguppZBIyVTWAPoChzM/FBkpqBVl\r\nUv2v3cE3UIfPENm5qWegUmmBg3yTLgD+MXyI6zter+DDUT9e0UWeaOZrsJvCpBUh\r\n9eLxUMpiKg64OARfl7wjEgorBgEEAZdVAQUBAQdALSF4rszFFAhisXD/7ZKytW1M\r\nLSWGPxW4sLNezkhKfX0DAQgHiHgEGBYIACAWIQRK8EwUs6FchRaOGmc7RguppZBI\r\nyQUCX5e8IwIbDAAKCRA7RguppZBIyUzLAQCDNMwKtq1zR2KHm9F0Fvp66vv2grX1\r\nj0TRb5sEayG9YQEA5ap7JltKc4iVThzu7bY1D+sZ3KbXetecf+QQv6YrwAE=\r\n=n3Jr\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n",
    "public_key": "xjMEX5e8IxYJKwYBBAHaRw8BAQdAsbKSTsqzMQSUdWv/UQBfYf+HD9/+dzCT+zVNIvZRQ/c=",
    "emails": [
      {
        "email": "usrename@example.com",
        "verified": true
      }
    ],
    "subkeys": [
      {
        "id": 1070012,
        "primary_key_id": 1070011,
        "key_id": "8EF2411709BAC3A4",
        "raw_key": null,
        "public_key": "zjgEX5e8IxIKKwYBBAGXVQEFAQEHQC0heK7MxRQIYrFw/+2SsrVtTC0lhj8VuLCzXs5ISn19AwEIBw==",
        "emails": [

        ],
        "subkeys": [

        ],
        "can_sign": false,
        "can_encrypt_comms": true,
        "can_encrypt_storage": true,
        "can_certify": false,
        "created_at": "2020-11-09T06:29:59.000Z",
        "expires_at": null
      }
    ],
    "can_sign": true,
    "can_encrypt_comms": false,
    "can_encrypt_storage": false,
    "can_certify": true,
    "created_at": "2020-11-09T06:29:59.000Z",
    "expires_at": null
  },
  {
    "id": 1043333,
    "primary_key_id": null,
    "key_id": "B4DA3BAE7E20B81C",
    "raw_key": null,
    "public_key": null,
    "emails": [
    ],
    "subkeys": [
    ],
    "can_sign": true,
    "can_encrypt_comms": false,
    "can_encrypt_storage": false,
    "can_certify": true,
    "created_at": "2020-10-13T22:07:23.000Z",
    "expires_at": null
  }
]
`
)

type testResponse struct {
	text   string
	reader io.ReadCloser
}

func newtestResponse1() *testResponse {
	return &testResponse{text: inputText1, reader: ioutil.NopCloser(strings.NewReader(inputText1))}
}
func newtestResponse2() *testResponse {
	return &testResponse{text: inputText2, reader: ioutil.NopCloser(strings.NewReader(inputText2))}
}
func (r *testResponse) Request() *http.Request            { return nil }
func (r *testResponse) Header() http.Header               { return nil }
func (r *testResponse) Close()                            {}
func (r *testResponse) Body() io.ReadCloser               { return r.reader }
func (r *testResponse) DumpBodyAndClose() ([]byte, error) { return []byte(r.text), nil }

var _ fetch.Response = (*testResponse)(nil)

type testClient struct {
	resp fetch.Response
}

func newtestClient1() *testClient {
	return &testClient{resp: newtestResponse1()}
}
func newtestClient2() *testClient {
	return &testClient{resp: newtestResponse2()}
}
func (c *testClient) Get(u *url.URL, opts ...fetch.RequestOpts) (fetch.Response, error) {
	return c.resp, nil
}
func (c *testClient) Post(u *url.URL, payload io.Reader, opts ...fetch.RequestOpts) (fetch.Response, error) {
	return c.resp, nil
}

var _ fetch.Client = (*testClient)(nil)

func TestGet(t *testing.T) {
	testCases := []struct {
		username string
	}{
		{username: "username"},
	}

	for _, tc := range testCases {
		b, err := github.GetKey(context.Background(), newtestClient1(), tc.username, "")
		if err != nil {
			t.Errorf("github.Get() is \"%+v\", want nil", err)
			fmt.Printf("Info: %+v\n", err)
		} else {
			_, _ = bytes.NewReader(b).WriteTo(os.Stdout)
		}
	}
}

func TestGetKey(t *testing.T) {
	testCases := []struct {
		username string
		kid      string
		err      error
	}{
		{username: "username", kid: "3B460BA9A59048C9", err: nil},
		{username: "username", kid: "0x3B460BA9A59048C9", err: nil},
		{username: "username", kid: "B4DA3BAE7E20B81C", err: ecode.ErrNoKey},
		{username: "username", kid: "0x00", err: ecode.ErrNoKey},
	}

	for _, tc := range testCases {
		b, err := github.GetKey(context.Background(), newtestClient2(), tc.username, tc.kid)
		if !errors.Is(err, tc.err) {
			t.Errorf("github.Get() is \"%+v\", want \"%+v\"", err, tc.err)
			fmt.Printf("Info: %+v\n", err)
		} else if err == nil {
			_, _ = bytes.NewReader(b).WriteTo(os.Stdout)
		}
	}
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
