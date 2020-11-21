package ecode

import (
	"fmt"
	"testing"
)

func TestNumError(t *testing.T) {
	testCases := []struct {
		err error
		str string
	}{
		{err: ECode(0), str: "unknown error (0)"},
		{err: ErrNullPointer, str: "null reference instance"},
		{err: ErrInvalidOption, str: "invalid option"},
		{err: ErrArmorText, str: "cannot find OpenPGP armor boundary"},
		{err: ErrInvalidWhence, str: "invalid whence"},
		{err: ErrInvalidOffset, str: "invalid offset"},
		{err: ErrUserID, str: "no user id"},
		{err: ErrGitHubUserID, str: "no GitHub user id"},
		{err: ErrNoKey, str: "not exist OpenPGP key"},
		{err: ErrNoURL, str: "no URL"},
		{err: ErrInvalidRequest, str: "invalid request"},
		{err: ErrEmptyKeyServer, str: "empty name of key serve"},
		{err: ErrHTTPStatus, str: "bad HTTP(S) status"},
		{err: ECode(13), str: "unknown error (13)"},
	}

	for _, tc := range testCases {
		errStr := tc.err.Error()
		if errStr != tc.str {
			t.Errorf("\"%v\" != \"%v\"", errStr, tc.str)
		}
		fmt.Printf("Info(TestNumError): %+v\n", tc.err)
	}
}

/* Copyright 2019,2020 Spiegel
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
