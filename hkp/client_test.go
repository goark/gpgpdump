package hkp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/spiegel-im-spiegel/errs"
)

func TestClient(t *testing.T) {
	testCases := []struct {
		host string
		uid  string
	}{
		{host: "keys.gnupg.net", uid: "0x69ECE048"},
	}

	for _, tc := range testCases {
		resp, err := New(tc.host).Client(context.TODO(), nil).Get(tc.uid)
		if err != nil {
			t.Errorf("Client.Get(\"%v\") is \"%v\", want nil", tc.uid, errs.Cause(err))
			fmt.Printf("Info: %+v\n", err)
		} else {
			_, _ = io.Copy(os.Stdout, bytes.NewReader(resp))
		}
	}
}

func TestClientErr(t *testing.T) {
	testCases := []struct {
		host string
		uid  string
	}{
		{host: "test.server", uid: "0x69ECE048"},
	}

	for _, tc := range testCases {
		_, err := New(tc.host).Client(context.TODO(), nil).Get(tc.uid)
		if errs.Cause(err) == nil {
			t.Errorf("Client.Get(\"%v\") is nil, not want nil", tc.uid)
		}
		fmt.Printf("Info: %+v\n", err)
	}
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
