package ecode

import (
	"fmt"
	"testing"

	"github.com/spiegel-im-spiegel/errs"
)

func TestNumError(t *testing.T) {
	testCases := []struct {
		err error
		str string
	}{
		{err: ECode(0), str: "Unknown error (0)"},
		{err: ErrNullPointer, str: "Null reference instance"},
		{err: ErrInvalidOption, str: "Invalid option"},
		{err: ErrArmorText, str: "Cannot find OpenPGP armor boundary"},
		{err: ErrInvalidWhence, str: "Invalid whence"},
		{err: ErrInvalidOffset, str: "Invalid offset"},
		{err: ErrUserID, str: "No user id"},
		{err: ErrEmptyKeyServer, str: "Empty name of key serve"},
		{err: ErrHTTPStatus, str: "Bad HTTP(S) status"},
		{err: ECode(9), str: "Unknown error (9)"},
	}

	for _, tc := range testCases {
		errStr := tc.err.Error()
		if errStr != tc.str {
			t.Errorf("\"%v\" != \"%v\"", errStr, tc.str)
		}
		fmt.Printf("Info(TestNumError): %+v\n", tc.err)
	}
}

func TestNumErrorEquality(t *testing.T) {
	testCases := []struct {
		err1 error
		err2 error
		res  bool
	}{
		{err1: nil, err2: nil, res: true},
		{err1: nil, err2: ErrNullPointer, res: false},
		{err1: ErrNullPointer, err2: ErrNullPointer, res: true},
		{err1: ErrNullPointer, err2: errs.Wrap(ErrNullPointer, "wrapping error"), res: false},
		{err1: ErrNullPointer, err2: ECode(0), res: false},
		{err1: ErrNullPointer, err2: nil, res: false},
	}

	for _, tc := range testCases {
		res := errs.Is(tc.err1, tc.err2)
		if res != tc.res {
			t.Errorf("\"%v\" == \"%v\" ? %v, want %v", tc.err1, tc.err2, res, tc.res)
		}
	}
}

func TestWrapError(t *testing.T) {
	testCases := []struct {
		err error
		msg string
		str string
	}{
		{err: ErrNullPointer, msg: "wrapping error", str: "wrapping error: Null reference instance"},
	}

	for _, tc := range testCases {
		we := errs.Wrap(tc.err, tc.msg)
		if we.Error() != tc.str {
			t.Errorf("wrapError.Error() == \"%v\", want \"%v\"", we.Error(), tc.str)
		}
		fmt.Printf("Info(TestWrapError): %+v\n", we)
	}
}

func TestWrapNilError(t *testing.T) {
	if we := errs.Wrap(nil, "null error"); we != nil {
		t.Errorf("Wrap(nil) == \"%v\", want nil.", we)
	}
}

func TestWrapfError(t *testing.T) {
	testCases := []struct {
		err error
		msg string
		str string
	}{
		{err: ErrNullPointer, msg: "wrapping error", str: "wrapping error: Null reference instance"},
	}

	for _, tc := range testCases {
		we := errs.Wrapf(tc.err, "%v", tc.msg)
		if we.Error() != tc.str {
			t.Errorf("wrapError.Error() == \"%v\", want \"%v\"", we.Error(), tc.str)
		}
		fmt.Printf("Info(TestWrapfError): %+v\n", we)
	}
}

func TestWrapfNilError(t *testing.T) {
	if we := errs.Wrapf(nil, "%v", "null error"); we != nil {
		t.Errorf("Wrapf(nil) == \"%v\", want nil.", we)
	}
}

func TestWrapErrorEquality(t *testing.T) {
	testCases := []struct {
		err1 error
		err2 error
		res  bool
	}{
		{err1: nil, err2: errs.Wrap(ErrNullPointer, "wrapping error"), res: false},
		{err1: errs.Wrap(ErrNullPointer, "wrapping error"), err2: ErrNullPointer, res: true},
		{err1: errs.Wrap(ErrNullPointer, "wrapping error"), err2: errs.Wrap(ECode(0), "wrapping error"), res: false},
		{err1: errs.Wrap(ErrNullPointer, "wrapping error"), err2: ECode(0), res: false},
		{err1: errs.Wrap(ErrNullPointer, "wrapping error"), err2: nil, res: false},
	}

	for _, tc := range testCases {
		res := errs.Is(tc.err1, tc.err2)
		if res != tc.res {
			t.Errorf("\"%v\" == \"%v\" ? %v, want %v", tc.err1, tc.err2, res, tc.res)
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
