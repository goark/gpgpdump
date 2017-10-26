package facade

import (
	"os"
	"testing"
)

type ecodeTestCase struct { //Test case for ExitCode
	ec  ExitCode
	v   int
	str string
}

var ecodeTests []ecodeTestCase //Test cases for ExitCode

func TestMain(m *testing.M) {
	ecodeTests = []ecodeTestCase{
		{Normal, 0, "normal end"},
		{Abnormal, 1, "abnormal end"},
		{ExitCode(2), 2, "unknown"},
	}

	//start test
	code := m.Run()

	//termination
	os.Exit(code)
}

func TestExitCode(t *testing.T) {
	for _, testCase := range ecodeTests {
		if testCase.ec.Int() != testCase.v {
			t.Errorf("ExitCode.Int()  = %v, want %v.", testCase.ec.Int(), testCase.v)
		}
		if testCase.ec.String() != testCase.str {
			t.Errorf("ExitCode.String()  = %v, want %v.", testCase.ec.String(), testCase.str)
		}
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
