package facade

//ExitCode is OS exit code enumeration class
type ExitCode int

const (
	//ExitNormal is OS exit code "normal"
	ExitNormal ExitCode = iota
	//ExitAbnormal is OS exit code "abnormal"
	ExitAbnormal
)

//Int convert integer value
func (c ExitCode) Int() int {
	return int(c)
}

//Stringer method
func (c ExitCode) String() string {
	switch c {
	case ExitNormal:
		return "normal end"
	case ExitAbnormal:
		return "abnormal end"
	default:
		return "unknown"
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
