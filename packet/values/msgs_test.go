package values

import "testing"

var names = Msgs{
	1: "Name1",
}

func TestMsgsGetNormal(t *testing.T) {
	res := names.Get(1, "Unknown")
	if res != "Name1" {
		t.Errorf("Msgs.Get() = \"%v\", want \"Name1\".", res)

	}
}

func TestMsgsGetNG(t *testing.T) {
	res := names.Get(0, "Unknown")
	if res != "Unknown" {
		t.Errorf("Msgs.Get() = \"%v\", want \"Unknown\".", res)

	}
}

/* Copyright 2016 Spiegel
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
