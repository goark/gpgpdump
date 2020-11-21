package hkp

import "testing"

func TestServer(t *testing.T) {
	testCases := []struct {
		host string
		url  string
	}{
		{host: "test.server", url: "http://test.server:11371"},
	}

	for _, tc := range testCases {
		svr := New(tc.host)
		str := svr.String()
		if str != tc.url {
			t.Errorf("Server(\"%v\") is %v, want %v", tc.host, str, tc.url)
		}
	}
}

func TestServer2(t *testing.T) {
	testCases := []struct {
		host string
		port int
		prt  Protocol
		url  string
	}{
		{host: "test.server", port: 80, prt: HKPS, url: "https://test.server:80"},
		{host: "test.server", port: 80, prt: Protocol(0), url: "http://test.server:80"},
	}

	for _, tc := range testCases {
		svr := New(tc.host, WithPort(tc.port), WithProtocol(tc.prt))
		str := svr.String()
		if str != tc.url {
			t.Errorf("Server(\"%v\") is %v, want %v", tc.host, str, tc.url)
		}
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
