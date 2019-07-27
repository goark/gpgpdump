package hkp

import (
	"fmt"
	"net/http"
)

//Protocol is kind of HKP protocols
type Protocol int

const (
	HKP  Protocol = iota + 1 //HTTP Keyserver Protocol
	HKPS                     //HKP over HTTPS
)

var protocolMap = map[Protocol]string{
	HKP:  "http",
	HKPS: "https",
}

func (p Protocol) String() string {
	if s, ok := protocolMap[p]; ok {
		return s
	}
	return protocolMap[HKP]
}

//Server is information of OpenPGP key server
type Server struct {
	prt  Protocol //HKP protocol
	host string   //OpenPGP key server host name
	port int      //port number of OpenPGP key server
}

//ServerOptFunc is self-referential function for functional options pattern
type ServerOptFunc func(*Server)

// New returns a new Server instance
func New(host string, opts ...ServerOptFunc) *Server {
	s := &Server{prt: HKP, host: host, port: 11371}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

//WithProtocol returns function for setting Reader
func WithProtocol(p Protocol) ServerOptFunc {
	return func(s *Server) {
		s.prt = p
	}
}

//WithPort returns function for setting Reader
func WithPort(port int) ServerOptFunc {
	return func(s *Server) {
		s.port = port
	}
}

//Client returns new Client instance for HKP client
func (s *Server) Client() *Client {
	return &Client{
		server: s,
		client: &http.Client{},
	}
}

func (s *Server) String() string {
	return fmt.Sprintf("%v://%v:%v", s.prt, s.host, s.port)
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
