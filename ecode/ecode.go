package ecode

import "errors"

var (
	ErrNullPointer    = errors.New("null reference instance")
	ErrInvalidOption  = errors.New("invalid option")
	ErrArmorText      = errors.New("cannot find OpenPGP armor boundary")
	ErrInvalidWhence  = errors.New("invalid whence")
	ErrInvalidOffset  = errors.New("invalid offset")
	ErrUserID         = errors.New("no user id")
	ErrGitHubUserID   = errors.New("no GitHub user id")
	ErrNoKey          = errors.New("not exist OpenPGP key")
	ErrNoURL          = errors.New("no URL")
	ErrInvalidRequest = errors.New("invalid request")
	ErrEmptyKeyServer = errors.New("empty name of key serve")
	ErrHTTPStatus     = errors.New("bad HTTP(S) status")
	ErrTooLarge       = errors.New("too laege decompressed data")
	ErrClipboard      = errors.New("cannot set --clipborad and --file options at onece")
)

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
