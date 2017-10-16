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

func TestTOMLNull(t *testing.T) {
	info := (*Info)(nil)
	res, err := info.TOML()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if string(res) != "" {
		t.Errorf("TOML() = %v, want nil.", string(res))
	}
}

func TestTOMLEmpty(t *testing.T) {
	info := NewInfo()
	res, err := info.TOML()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if string(res) != "" {
		t.Errorf("TOML() = %v, want nil.", string(res))
	}
}

func TestJSONNull(t *testing.T) {
	info := (*Info)(nil)
	res, err := info.JSON()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if string(res) != "" {
		t.Errorf("TOML() = %v, want nil.", string(res))
	}
}

func TestJSONEmpty(t *testing.T) {
	info := NewInfo()
	res, err := info.JSON()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if string(res) != "{}" {
		t.Errorf("TOML() = %v, want {}.", string(res))
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
