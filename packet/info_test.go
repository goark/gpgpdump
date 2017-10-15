package packet

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	//start test
	code := m.Run()

	//termination
	os.Exit(code)
}

func TestMarshalTOMLNull(t *testing.T) {
	info := (*Info)(nil)
	res, err := info.MarshalTOML()
	if err != nil {
		t.Errorf("MarshalTOML() err = %v, want nil.", err)
	}
	if string(res) != "" {
		t.Errorf("MarshalTOML() = %v, want nil.", string(res))
	}
}

func TestMarshalTOMLEmpty(t *testing.T) {
	info := &Info{}
	res, err := info.MarshalTOML()
	if err != nil {
		t.Errorf("MarshalTOML() err = %v, want nil.", err)
	}
	if string(res) != "" {
		t.Errorf("MarshalTOML() = %v, want nil.", string(res))
	}
}

func TestMarshalJSONNull(t *testing.T) {
	info := (*Info)(nil)
	res, err := info.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalTOML() err = %v, want nil.", err)
	}
	if string(res) != "" {
		t.Errorf("MarshalTOML() = %v, want nil.", string(res))
	}
}

func TestMarshalJSONEmpty(t *testing.T) {
	info := &Info{}
	res, err := info.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalTOML() err = %v, want nil.", err)
	}
	if string(res) != "{}" {
		t.Errorf("MarshalTOML() = %v, want {}.", string(res))
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
