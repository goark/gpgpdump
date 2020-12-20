package ecode

import "fmt"

//ECode is error codes for gpgpdump
type ECode int

const (
	ErrNullPointer ECode = iota + 1
	ErrInvalidOption
	ErrArmorText
	ErrInvalidWhence
	ErrInvalidOffset
	ErrUserID
	ErrGitHubUserID
	ErrNoKey
	ErrNoURL
	ErrInvalidRequest
	ErrHTTPStatus
	ErrEmptyKeyServer
	ErrTooLarge
	ErrClipboard
)

var errMessage = map[ECode]string{
	ErrNullPointer:    "null reference instance",
	ErrInvalidOption:  "invalid option",
	ErrArmorText:      "cannot find OpenPGP armor boundary",
	ErrInvalidWhence:  "invalid whence",
	ErrInvalidOffset:  "invalid offset",
	ErrUserID:         "no user id",
	ErrGitHubUserID:   "no GitHub user id",
	ErrNoKey:          "not exist OpenPGP key",
	ErrNoURL:          "no URL",
	ErrInvalidRequest: "invalid request",
	ErrEmptyKeyServer: "empty name of key serve",
	ErrHTTPStatus:     "bad HTTP(S) status",
	ErrTooLarge:       "too laege decompressed data",
	ErrClipboard:       "cannot set --clipborad and --file options at onece",
}

func (e ECode) Error() string {
	if s, ok := errMessage[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown error (%d)", int(e))
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
