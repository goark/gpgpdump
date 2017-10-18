package packet

import (
	"io"
	"os"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

func TestMain(m *testing.M) {
	//start test
	code := m.Run()

	//termination
	os.Exit(code)
}

const (
	sample1 = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`
)

const (
	result1 = `{}`
)

func TestParseNil(t *testing.T) {
	opts := options.NewOptions(
		options.Set(options.ArmorOpt, false),
		options.Set(options.JSONOpt, true),
	)
	reader, err := NewReader(nil, opts)
	if err != nil {
		t.Errorf("NewReader()  = %v, want nil error.", err)
		return
	}
	info, err := reader.Parse()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	str, err := info.JSON()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	if str != result1 {
		t.Errorf("Parse()  = \"%v\", want \"%v\".", str, result1)
	}
}

func TestParseNilASCII(t *testing.T) {
	opts := options.NewOptions(
		options.Set(options.ArmorOpt, true),
		options.Set(options.JSONOpt, true),
	)
	_, err := NewReader(nil, opts)
	if err != io.EOF {
		t.Errorf("NewReader()  = %v, want nil error.", err)
		return
	}
}

func TestParse(t *testing.T) {
	opts := options.NewOptions(
		options.Set(options.ArmorOpt, true),
		options.Set(options.JSONOpt, true),
	)
	reader, err := NewReader([]byte(sample1), opts)
	if err != nil {
		t.Errorf("NewReader()  = %v, want nil error.", err)
		return
	}
	info, err := reader.Parse()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	str, err := info.JSON()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	if str != result1 {
		t.Errorf("Parse()  = \"%v\", want \"%v\".", str, result1)
	}
}

/* Copyright 2017 Spiegel
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
