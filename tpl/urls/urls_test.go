// Copyright 2017 The Hugo Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package urls

import (
	"net/url"
	"testing"

	"github.com/gohugoio/hugo/htesting/hqt"

	qt "github.com/frankban/quicktest"
	"github.com/gohugoio/hugo/deps"
	"github.com/spf13/viper"
)

var ns = New(&deps.Deps{Cfg: viper.New()})

type tstNoStringer struct{}

func TestParse(t *testing.T) {
	t.Parallel()
	c := qt.New(t)

	for _, test := range []struct {
		rawurl interface{}
		expect interface{}
	}{
		{
			"http://www.google.com",
			&url.URL{
				Scheme: "http",
				Host:   "www.google.com",
			},
		},
		{
			"http://j@ne:password@google.com",
			&url.URL{
				Scheme: "http",
				User:   url.UserPassword("j@ne", "password"),
				Host:   "google.com",
			},
		},
		// errors
		{tstNoStringer{}, false},
	} {

		result, err := ns.Parse(test.rawurl)

		if b, ok := test.expect.(bool); ok && !b {
			c.Assert(err, qt.Not(qt.IsNil))
			continue
		}

		c.Assert(err, qt.IsNil)
		c.Assert(result,
			qt.CmpEquals(hqt.DeepAllowUnexported(&url.URL{}, url.Userinfo{})), test.expect)
	}
}

func TestImgixURL(t *testing.T) {
	t.Parallel()
	c := qt.New(t)

	for _, test := range []struct {
		path      interface{}
		param     interface{}
		serverURL interface{}
		token     interface{}
		expect    interface{}
	}{
		{"path", "", "server", "", "https://server/path"},
		{"path", "params", "server", "", "https://server/path?params"},
		{"https://domain.tld/path", "", "server", "", "https://server/https%3A%2F%2Fdomain.tld%2Fpath"},
		{"http://domain.tld/path", "", "server", "", "https://server/http%3A%2F%2Fdomain.tld%2Fpath"},
		{"https://domain.tld/path", "", "http://server.tld", "", "http://server.tld/https%3A%2F%2Fdomain.tld%2Fpath"},
		{"https://domain.tld/path", "", "https://server.tld", "", "https://server.tld/https%3A%2F%2Fdomain.tld%2Fpath"},
		{"https://domain.tld/path", "w=400", "http://server.tld", "", "http://server.tld/https%3A%2F%2Fdomain.tld%2Fpath?w=400"},
		{"https://domain.tld/path", "?w=400&h=500", "https://server.tld", "", "https://server.tld/https%3A%2F%2Fdomain.tld%2Fpath?w=400&h=500"},
		{"https://domain.tld/path", "?w=400&h=500", "https://server.tld", "token", "https://server.tld/https%3A%2F%2Fdomain.tld%2Fpath?w=400&h=500&s=935a95820d579a14a9671a14b2f1397a"},

		// errors
		{"no server", "-", "", "", false},
		{"no server", "", "", "", false},
		{"", "", "", "", false},
	} {

		result, err := ns.ImgixURL(test.path, test.param, test.serverURL, test.token)

		if b, ok := test.expect.(bool); ok && !b {
			c.Assert(err, qt.Not(qt.IsNil))
			continue
		}

		c.Assert(err, qt.IsNil)
		c.Assert(result, qt.Equals, test.expect)
	}
}
