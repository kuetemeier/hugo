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

// Package urls provides template functions to deal with URLs.
package urls

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"html/template"

	"net/url"

	"github.com/gohugoio/hugo/common/urls"
	"github.com/gohugoio/hugo/deps"
	_errors "github.com/pkg/errors"
	"github.com/spf13/cast"
)

// New returns a new instance of the urls-namespaced template functions.
func New(deps *deps.Deps) *Namespace {
	return &Namespace{
		deps:      deps,
		multihost: deps.Cfg.GetBool("multihost"),
	}
}

// Namespace provides template functions for the "urls" namespace.
type Namespace struct {
	deps      *deps.Deps
	multihost bool
}

// AbsURL takes a given string and converts it to an absolute URL.
func (ns *Namespace) AbsURL(a interface{}) (template.HTML, error) {
	s, err := cast.ToStringE(a)
	if err != nil {
		return "", nil
	}

	return template.HTML(ns.deps.PathSpec.AbsURL(s, false)), nil
}

// Parse parses rawurl into a URL structure. The rawurl may be relative or
// absolute.
func (ns *Namespace) Parse(rawurl interface{}) (*url.URL, error) {
	s, err := cast.ToStringE(rawurl)
	if err != nil {
		return nil, _errors.Wrap(err, "Error in Parse")
	}

	return url.Parse(s)
}

// RelURL takes a given string and prepends the relative path according to a
// page's position in the project directory structure.
func (ns *Namespace) RelURL(a interface{}) (template.HTML, error) {
	s, err := cast.ToStringE(a)
	if err != nil {
		return "", nil
	}

	return template.HTML(ns.deps.PathSpec.RelURL(s, false)), nil
}

// URLize returns the given argument formatted as URL.
func (ns *Namespace) URLize(a interface{}) (string, error) {
	s, err := cast.ToStringE(a)
	if err != nil {
		return "", nil
	}
	return ns.deps.PathSpec.URLize(s), nil
}

// Anchorize creates sanitized anchor names that are compatible with Blackfriday.
func (ns *Namespace) Anchorize(a interface{}) (string, error) {
	s, err := cast.ToStringE(a)
	if err != nil {
		return "", nil
	}
	return ns.deps.ContentSpec.SanitizeAnchorName(s), nil
}

// Ref returns the absolute URL path to a given content item.
func (ns *Namespace) Ref(in interface{}, args interface{}) (template.HTML, error) {
	p, ok := in.(urls.RefLinker)
	if !ok {
		return "", errors.New("invalid Page received in Ref")
	}
	argsm, err := ns.refArgsToMap(args)
	if err != nil {
		return "", err
	}
	s, err := p.Ref(argsm)
	return template.HTML(s), err
}

// RelRef returns the relative URL path to a given content item.
func (ns *Namespace) RelRef(in interface{}, args interface{}) (template.HTML, error) {
	p, ok := in.(urls.RefLinker)
	if !ok {
		return "", errors.New("invalid Page received in RelRef")
	}
	argsm, err := ns.refArgsToMap(args)
	if err != nil {
		return "", err
	}

	s, err := p.RelRef(argsm)
	return template.HTML(s), err
}

func (ns *Namespace) refArgsToMap(args interface{}) (map[string]interface{}, error) {
	var (
		s  string
		of string
	)

	v := args
	if _, ok := v.([]interface{}); ok {
		v = cast.ToStringSlice(v)
	}

	switch v := v.(type) {
	case map[string]interface{}:
		return v, nil
	case map[string]string:
		m := make(map[string]interface{})
		for k, v := range v {
			m[k] = v
		}
		return m, nil
	case []string:
		if len(v) == 0 || len(v) > 2 {
			return nil, fmt.Errorf("invalid numer of arguments to ref")
		}
		// These where the options before we introduced the map type:
		s = v[0]
		if len(v) == 2 {
			of = v[1]
		}
	default:
		var err error
		s, err = cast.ToStringE(args)
		if err != nil {
			return nil, err
		}

	}

	return map[string]interface{}{
		"path":         s,
		"outputFormat": of,
	}, nil
}

// RelLangURL takes a given string and prepends the relative path according to a
// page's position in the project directory structure and the current language.
func (ns *Namespace) RelLangURL(a interface{}) (template.HTML, error) {
	s, err := cast.ToStringE(a)
	if err != nil {
		return "", err
	}

	return template.HTML(ns.deps.PathSpec.RelURL(s, !ns.multihost)), nil
}

// AbsLangURL takes a given string and converts it to an absolute URL according
// to a page's position in the project directory structure and the current
// language.
func (ns *Namespace) AbsLangURL(a interface{}) (template.HTML, error) {
	s, err := cast.ToStringE(a)
	if err != nil {
		return "", err
	}

	return template.HTML(ns.deps.PathSpec.AbsURL(s, !ns.multihost)), nil
}

// ImgProxyURL takes a given string and converts it to an absolute URL according
// to a page's position in the project directory structure and the current
// language.
func (ns *Namespace) ImgProxyURL(args ...interface{}) (string, error) {

	url, err := cast.ToStringE(args[0])
	if err != nil {
		return "", err
	}

	process, err := cast.ToStringE(args[1])
	if err != nil {
		return "", err
	}

	key := ns.deps.Cfg.GetString("imgproxy.key")
	salt := ns.deps.Cfg.GetString("imgproxy.salt")
	serverURL := ns.deps.Cfg.GetString("imgproxy.serverurl")

	var keyBin, saltBin []byte

	if keyBin, err = hex.DecodeString(key); err != nil {
		return "", errors.New("imgproxy key expected to be a hex-encoded string in imgProxyURL")
	}

	if saltBin, err = hex.DecodeString(salt); err != nil {
		return "", errors.New("imgproxy salt expected to be a hex-encoded string in imgProxyURL")
	}

	encodedURL := base64.RawURLEncoding.EncodeToString([]byte(url))

	path := "/" + process + "/" + encodedURL

	h := hmac.New(sha256.New, keyBin)
	h.Write(saltBin)
	h.Write([]byte(path))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	ret := serverURL + "/" + signature + path

	return ret, err
}

// Regexp for all characters we should escape in a URI passed in.
var regexURLCharactersToEscape = regexp.MustCompile("([^ a-zA-Z0-9_.-])")

// This method replicates the beavhior of Ruby's CGI::escape in Go.
//
// Source: https://github.com/parkr/imgix-go/blob/master/imgix.go (MIT License)
//
// See:
//  - https://github.com/parkr/imgix-go/pull/1#issuecomment-109014369
//  - https://github.com/imgix/imgix-blueprint#securing-urls
func cgiEscape(s string) string {
	return regexURLCharactersToEscape.ReplaceAllStringFunc(s, func(s string) string {
		rune, _ := utf8.DecodeLastRuneInString(s)
		return "%" + strings.ToUpper(fmt.Sprintf("%x", rune))
	})
}

// ImgixURL builds an Imgix URL from an image path, (optional) process parameters and
// (optionally) signs this URL with a tokenized MD5 signature.
//
// Some code is borrowed / inspired from the Imgix GO library:
// https://github.com/parkr/imgix-go/blob/master/imgix.go (MIT License)
//
// See:
// - https://imgix.com
// - https://docs.imgix.com/setup/serving-images
// - https://docs.imgix.com/setup/securing-images
// - https://docs.imgix.com/apis/url
func (ns *Namespace) ImgixURL(args ...interface{}) (string, error) {

	if len(args) < 1 {
		return "", errors.New("need at least 1 argument to imgixURL")
	}

	// get path to image (may be a path or full URL) - first argument
	path, err := cast.ToStringE(args[0])
	if err != nil {
		return "", err
	}

	if path == "" {
		return "", errors.New("empty path given to imgixURL")
	}

	// get params - (optional) second argument (default: "")
	params := ""
	if len(args) > 1 {
		params, err = cast.ToStringE(args[1])
		if err != nil {
			return "", err
		}
	}

	// default
	serverURL := ""
	secureURL := false
	token := ""

	if len(args) <= 2 {
		// no more arguments, read values from cfg
		serverURL = ns.deps.Cfg.GetString("imgix.serverurl")
		secureURL = ns.deps.Cfg.GetBool("imgix.secureURL")
		token = ns.deps.Cfg.GetString("imgix.token")

	} else if len(args) == 3 {
		// one more, this musst be a cfg id

		cfgID, err := cast.ToStringE(args[2])
		if err != nil {
			return "", err
		}

		serverURL = ns.deps.Cfg.GetString("imgix." + cfgID + ".serverurl")
		secureURL = ns.deps.Cfg.GetBool("imgix." + cfgID + ".secureURL")
		token = ns.deps.Cfg.GetString("imgix." + cfgID + ".token")

	} else if len(args) == 4 {
		// four arguments, this means, 3rd is a server URL and 4th a token

		// when we have a server URL and a token, secureURL is true by default
		secureURL = true

		serverURL, err = cast.ToStringE(args[2])
		if err != nil {
			return "", err
		}

		token, err = cast.ToStringE(args[3])
		if err != nil {
			return "", err
		}

	} else if len(args) > 4 {
		return "", errors.New("to many parameters to imgixURL")
	}

	// Matches http:// and https://
	var RegexpHTTPAndS = regexp.MustCompile("https?://")

	// let's check to be sure:

	// for empty serverURL
	if serverURL == "" {
		return "", errors.New("no server URL configured or passed to imgixURL")
	}

	// a server URL without http or https (than https will be default)
	if !RegexpHTTPAndS.MatchString(serverURL) {
		serverURL = "https://" + serverURL
	}

	// a request for a signed URL, but we have no token
	if secureURL && (token == "") {
		return "", errors.New("URL shoud be secured, but no token configured or passed to imgixURL")
	}

	// If we are given a fully-qualified URL, escape it per the note located
	// near the `cgiEscape` function definition
	if RegexpHTTPAndS.MatchString(path) {
		path = cgiEscape(path)
	}

	// Add a leading slash if one does not exist:
	//     "users/1.png" -> "/users/1.png"
	//     "https://path/to/image" -> "/https%3A%2F%2Fpath%2Fto%2Fimage.jpg"
	if strings.Index(path, "/") != 0 {
		path = "/" + path
	}

	pathWithParams := path

	if params != "" {
		if strings.Index(params, "?") == 0 {
			pathWithParams = pathWithParams + params
		} else {
			pathWithParams = pathWithParams + "?" + params
		}
	}

	url := serverURL + pathWithParams

	if secureURL {
		// calculate signature
		signatureBase := token + pathWithParams
		h := md5.New()
		io.WriteString(h, signatureBase)
		signature := h.Sum(nil)

		// append signature
		if len(params) != 0 {
			url = url + "&s=" + hex.EncodeToString(signature)
		} else {
			url = url + "?s=" + hex.EncodeToString(signature)
		}
	}

	return url, err
}
