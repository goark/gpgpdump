package hkp_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/goark/errs"
	"github.com/goark/fetch"
	"github.com/goark/gpgpdump/hkp"
)

var inputText = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" >
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Public Key Server -- Get "0x44ce6900e2b307a4 "</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
<style type="text/css">
/*<![CDATA[*/
.uid { color: green; text-decoration: underline; }
.warn { color: red; font-weight: bold; }
/*]]>*/
</style></head><body><h1>Public Key Server -- Get "0x44ce6900e2b307a4 "</h1>
<pre>
-----BEGIN PGP PUBLIC KEY BLOCK-----
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
</pre>
</body></html>
`

type testResponse struct {
	reader io.ReadCloser
}

func newtestResponse() *testResponse {
	return &testResponse{reader: io.NopCloser(strings.NewReader(inputText))}
}
func (r *testResponse) Request() *http.Request            { return nil }
func (r *testResponse) Header() http.Header               { return nil }
func (r *testResponse) Close()                            {}
func (r *testResponse) Body() io.ReadCloser               { return r.reader }
func (r *testResponse) DumpBodyAndClose() ([]byte, error) { return []byte(inputText), nil }

var _ fetch.Response = (*testResponse)(nil)

type testClient struct{}

var _ fetch.Client = (*testClient)(nil)

func (c *testClient) Get(u *url.URL, opts ...fetch.RequestOpts) (fetch.Response, error) {
	return newtestResponse(), nil
}
func (c *testClient) Post(u *url.URL, payload io.Reader, opts ...fetch.RequestOpts) (fetch.Response, error) {
	return newtestResponse(), nil
}

func TestFetch(t *testing.T) {
	testCases := []struct {
		host string
		uid  string
	}{
		{host: "keys.gnupg.net", uid: "0x7E20B81C"},
	}

	for _, tc := range testCases {
		r, err := hkp.New(tc.host).Fetch(context.Background(), &testClient{}, tc.uid)
		if err != nil {
			t.Errorf("Client.Get(\"%v\") is \"%v\", want nil", tc.uid, errs.Cause(err))
			fmt.Printf("Info: %+v\n", err)
		} else {
			_, _ = io.Copy(os.Stdout, r)
			r.Close()
		}
	}
}

/* Copyright 2019-2021 Spiegel
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
