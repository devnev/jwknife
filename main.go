// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func main() {
	if err := run(os.Args); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}

const usagetpl = `
Manipulate & Convert JWK sets.
- Read any number of keys in PEM, JWK or JWKS format into a single JWK set.
- Output some or all of the JWKs as a JWK set or PEM.

Example:
	%[1]s read -pem -path=my.pem gen -rsa=2048 -set=alg=RS256 -set=use=sig write -jwks -path=my-jwk.json

Available subcommands:
	read [-jwks] [-pem] [-insecure] [-path=path] [-url=url] [-schemes=scheme[,...]]
	gen [-rsa=bits] [-ec=curve] [-setstr=key=str] [-setjson=key=json]
	write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-mode=octal-mode] [-url=url] [-post] [-put] [-insecure]
`

func usage() string {
	return fmt.Sprintf(strings.TrimSpace(usagetpl), filepath.Base(os.Args[0]))
}

func run(args []string) error {
	if len(args) <= 1 {
		fmt.Println(usage())
		return nil
	}
	cmds := [][]string{[]string{"opts"}}
	for _, arg := range args[1:] {
		if arg == "--help" {
			fmt.Println(usage())
			return nil
		}
		if strings.HasPrefix(arg, "-") {
			cmds[len(cmds)-1] = append(cmds[len(cmds)-1], arg)
		} else {
			cmds = append(cmds, []string{arg})
		}
	}

	set := jwk.NewSet()
	for _, cmd := range cmds {
		switch cmd[0] {
		case "opts":
			if err := handleOpts(cmd[1:]); err != nil {
				return err
			}
		case "read":
			if err := handleRead(cmd[1:], set); err != nil {
				return err
			}
		case "gen":
			if err := handleGen(cmd[1:], set); err != nil {
				return err
			}
		case "write":
			if err := handleWrite(cmd[1:], set); err != nil {
				return err
			}
		default:
			return errors.New("unknown command")
		}
	}

	return nil
}

func handleOpts(args []string) error {
	if len(args) > 0 {
		return errors.New("invalid option")
	}
	return nil
}

func handleRead(args []string, set jwk.Set) error {
	var (
		jwks     bool
		pem      bool
		insecure bool
		path     *string
		url_     *string
		schemes  *[]string
	)
	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimPrefix(arg[1:], "-"), "=")
		switch name {
		case "jwks":
			if jwks {
				return errors.New("duplicate flag --jwks")
			}
			if found {
				return errors.New("--jwks does not take a value")
			}
			jwks = true
		case "pem":
			if pem {
				return errors.New("duplicate flag --pem")
			}
			if found {
				return errors.New("--pem does not take a value")
			}
			pem = true
		case "insecure":
			if insecure {
				return errors.New("duplicate flag --insecure")
			}
			if found {
				return errors.New("--insecure does not take a value")
			}
			insecure = true
		case "path":
			if path != nil {
				return errors.New("duplicate flag --path")
			}
			if value == "" {
				return errors.New("missing or empty value for --path")
			}
			path = new(string)
			*path = value
		case "url":
			if url_ != nil {
				return errors.New("duplicate flag --path")
			}
			if value == "" {
				return errors.New("missing or empty value for --url")
			}
			url_ = new(string)
			*url_ = value
		case "schemes":
			if schemes != nil {
				return errors.New("duplicate flag --schemes")
			}
			if value == "" {
				return errors.New("missing or empty value for --schemes")
			}
			schemes = new([]string)
			*schemes = strings.Split(arg, ",")
			for _, scheme := range *schemes {
				switch scheme {
				case "file", "http", "https":
				default:
					return errors.New("unsupported scheme")
				}
			}
		default:
			return errors.New("invalid flag")
		}
	}

	if jwks && pem {
		return errors.New("cannot specify both --jwks and --pem")
	} else if !pem {
		jwks = true
	}

	if url_ == nil && path == nil {
		return errors.New("must specify either --path or --url")
	}
	if url_ != nil && path != nil {
		return errors.New("cannot specify both --path and --url")
	}

	if url_ != nil {
		if schemes != nil && !insecure && slices.Contains(*schemes, "http") {
			return errors.New("scheme http invalid without --insecure")
		}
		if schemes == nil {
			schemes = new([]string)
			if insecure {
				*schemes = []string{"file", "https"}
			} else {
				*schemes = []string{"file", "http", "https"}
			}
		}
		parsed, err := url.Parse(*url_)
		if err != nil {
			return err
		}
		if !slices.Contains(*schemes, parsed.Scheme) {
			return errors.New("blocked url scheme")
		}
		var kind = "jwk"
		if pem {
			kind = "pem"
		}
		return readFromURL(parsed, kind, set)
	}

	if path != nil {
		if insecure {
			return errors.New("can only specify --insecure with --url")
		}
		if schemes != nil {
			return errors.New("can only specify --schemes with --url")
		}
		var kind = "jwk"
		if pem {
			kind = "pem"
		}
		return readFromPath(*path, kind, set)
	}

	panic("unreachable")
}

func handleGen(args []string, set jwk.Set) error {
	var (
		rsabits *int
		curve   *elliptic.Curve
		props   = make(map[string]any)
	)

	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimPrefix(arg[1:], "-"), "=")
		switch name {
		case "rsa":
			if rsabits != nil {
				return errors.New("duplicate flag --rsa")
			}
			if value == "" {
				return errors.New("missing or empty value for --rsa")
			}
			rsabits = new(int)
			*rsabits = map[string]int{
				"2048": 2048,
				"3072": 3072,
				"4096": 4096,
			}[value]
			if *rsabits == 0 {
				return errors.New("unsupported bit-length for --rsa")
			}
		case "ec":
			if curve != nil {
				return errors.New("duplicate flag --ec")
			}
			if value == "" {
				return errors.New("missing or empty value for --ec")
			}
			var ecalgo jwa.EllipticCurveAlgorithm
			if err := ecalgo.Accept(value); err != nil {
				return errors.New("invalid EC algorithm")
			}
			curve = new(elliptic.Curve)
			*curve, found = jwk.CurveForAlgorithm(ecalgo)
			if !found {
				return errors.New("unsupported curve algorithm")
			}
		case "setstr":
			if value == "" {
				return errors.New("missing or empty value for --set")
			}
			name, value, found = strings.Cut(value, "=")
			if !found {
				return errors.New("--set value must be key=value format")
			}
			if _, exists := props[name]; exists {
				return errors.New("duplicate --set key")
			}
			props[name] = value
		case "setjson":
			if value == "" {
				return errors.New("missing or empty value for --set")
			}
			name, value, found = strings.Cut(value, "=")
			if !found {
				return errors.New("--set value must be key=value format")
			}
			if _, exists := props[name]; exists {
				return errors.New("duplicate --set key")
			}
			var obj any
			if err := json.Unmarshal([]byte(value), &obj); err != nil {
				return err
			}
			props[name] = obj
		default:
			return errors.New("invalid flag")
		}
	}

	if rsabits == nil && curve == nil {
		return errors.New("must specify either --rsa or --ec")
	}
	if rsabits != nil && curve != nil {
		return errors.New("cannot specify both --rsa and --ec")
	}

	if rsabits != nil {
		rawKey, err := rsa.GenerateKey(rand.Reader, *rsabits)
		if err != nil {
			return err
		}
		return addKey(rawKey, props, set)
	}

	if curve != nil {
		rawKey, err := ecdsa.GenerateKey(*curve, rand.Reader)
		if err != nil {
			return err
		}
		return addKey(rawKey, props, set)
	}

	panic("unreachable")
}

func handleWrite(args []string, set jwk.Set) error {
	var (
		pubkey   bool
		fullkey  bool
		jwks     bool
		pem      bool
		path     *string
		mode     *uint32
		post     bool
		put      bool
		url_     *url.URL
		insecure bool
	)

	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimPrefix(arg[1:], "-"), "=")
		switch name {
		case "pubkey":
			if pubkey {
				return errors.New("duplicate flag --pubkey")
			}
			if found {
				return errors.New("--pubkey does not take a value")
			}
			pubkey = true
		case "fullkey":
			if fullkey {
				return errors.New("duplicate flag --fullkey")
			}
			if found {
				return errors.New("--fullkey does not take a value")
			}
			fullkey = true
		case "jwks":
			if jwks {
				return errors.New("duplicate flag --jwks")
			}
			if found {
				return errors.New("--jwks does not take a value")
			}
			jwks = true
		case "pem":
			if pem {
				return errors.New("duplicate flag --pem")
			}
			if found {
				return errors.New("--pem does not take a value")
			}
			pem = true
		case "path":
			if path != nil {
				return errors.New("duplicate flag --path")
			}
			if value == "" {
				return errors.New("missing or empty value for --path")
			}
			path = new(string)
			*path = value
		case "mode":
			if mode != nil {
				return errors.New("duplicate flag --path")
			}
			if value == "" {
				return errors.New("missing or empty value for --mode")
			}
			parsed, err := strconv.ParseUint(value, 8, 32)
			if err != nil {
				return err
			}
			if (parsed & ^uint64(0777)) != 0 {
				return errors.New("invalid mode")
			}
			mode = new(uint32)
			*mode = uint32(parsed)
		case "url":
			if url_ != nil {
				return errors.New("duplicate flag --url")
			}
			if value == "" {
				return errors.New("missing or empty value for --url")
			}
			parsed, err := url.Parse(value)
			if err != nil {
				return err
			}
			url_ = parsed
		case "post":
			if post {
				return errors.New("duplicate flag --post")
			}
			if found {
				return errors.New("--post does not take a value")
			}
			post = true
		case "put":
			if put {
				return errors.New("duplicate flag --put")
			}
			if found {
				return errors.New("--put does not take a value")
			}
			put = true
		case "insecure":
			if insecure {
				return errors.New("duplicate flag --insecure")
			}
			if found {
				return errors.New("--insecure does not take a value")
			}
			insecure = true
		default:
			return errors.New("invalid flag")
		}
	}

	if jwks && pem {
		return errors.New("cannot specify both --jwks and --pem")
	} else if !pem {
		jwks = true
	}

	if pubkey && fullkey {
		return errors.New("cannot specify both --pubkey and --fullkey")
	} else if !fullkey {
		pubkey = true
	}

	encode := func() (string, error) {
		if pem {
			var builder strings.Builder
			keys := set.Keys(context.Background())
			for keys.Next(context.Background()) {
				var key jwk.Key = keys.Pair().Value.(jwk.Key)
				if pubkey {
					var err error
					if key, err = key.PublicKey(); err != nil {
						return "", err
					}
				}
				b, err := jwk.EncodePEM(key)
				if err != nil {
					return "", err
				}
				_, _ = builder.WriteString(string(b))
			}
			return builder.String(), nil
		} else {
			if pubkey {
				pubset := jwk.NewSet()
				keys := set.Keys(context.Background())
				for keys.Next(context.Background()) {
					var key jwk.Key = keys.Pair().Value.(jwk.Key)
					var err error
					if key, err = key.PublicKey(); err != nil {
						return "", err
					}
					if err := pubset.AddKey(key); err != nil {
						return "", err
					}
				}
				set = pubset
			}
			b, err := json.Marshal(set)
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
	}

	if url_ == nil && path == nil {
		return errors.New("must specify either --path or --url")
	}
	if url_ != nil && path != nil {
		return errors.New("cannot specify both --path and --url")
	}

	if path != nil {
		if post {
			return errors.New("cannot specify both --path and --post")
		}
		if put {
			return errors.New("cannot specify both --path and --put")
		}
		if insecure {
			return errors.New("cannot specify both --path and --insecure")
		}

		encoded, err := encode()
		if err != nil {
			return err
		}
		var filemode os.FileMode = 0400
		if mode != nil {
			filemode = os.FileMode(*mode)
		}
		return os.WriteFile(*path, []byte(encoded), filemode)
	}

	if url_ != nil {
		if post && put {
			return errors.New("cannot specify both --post and --put")
		}
		switch {
		case url_.Scheme == "https":
		case insecure && url_.Scheme == "http":
		default:
			return errors.New("unsupported scheme for --url")
		}

		encoded, err := encode()
		if err != nil {
			return err
		}
		var method = http.MethodPut
		if post {
			method = http.MethodPost
		}
		req, err := http.NewRequest(method, url_.String(), strings.NewReader(encoded))
		if err != nil {
			// should not be reachable
			panic(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return errors.New("received non-OK response")
		}
		return nil
	}

	panic("unreachable")
}

func readFromPath(arg string, kind string, set jwk.Set) error {
	contents, err := os.ReadFile(arg)
	if err != nil {
		return err
	}
	return parseContents(contents, kind, set)
}

func readFromURL(from *url.URL, kind string, set jwk.Set) error {
	if from.Scheme == "file" {
		if from.Opaque != "" {
			path, err := url.PathUnescape(from.Opaque)
			if err != nil {
				return err
			}
			return readFromPath(path, kind, set)
		}
		if from.Host == "" || from.Host == "localhost" {
			if !from.ForceQuery && from.RawQuery == "" && from.Fragment == "" {
				return readFromPath(from.Path, kind, set)
			}
		}
		return errors.New("unsupported file URL")
	}

	if from.Scheme == "https" || from.Scheme == "http" {
		resp, err := http.Get(from.String())
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return errors.New("URL returned non-OK status")
		}
		var buf bytes.Buffer
		_, err = io.Copy(&buf, resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		if err != nil {
			return err
		}

		return parseContents(buf.Bytes(), kind, set)
	}

	return errors.New("unsupported URL scheme")
}

func parseContents(contents []byte, kind string, set jwk.Set) error {
	read, err := jwk.Parse(contents, jwk.WithPEM(kind == "pem"))
	if err != nil {
		return err
	}
	iter := read.Keys(context.Background())
	for iter.Next(context.Background()) {
		if err = (set).AddKey(iter.Pair().Value.(jwk.Key)); err != nil {
			return err
		}
	}
	return nil
}

func addKey(rawKey any, settings map[string]any, set jwk.Set) error {
	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		return err
	}

	// Convert to untyped JSON so we can set arbitrary structured values from flags
	enc, err := json.Marshal(key)
	if err != nil {
		// this shouldn't be reachable as jwk.Keys should always be marshalable
		panic(err)
	}
	var obj map[string]any
	if err = json.Unmarshal(enc, &obj); err != nil {
		// this shouldn't be reachable, as marshaling a jwk.Key should always produce a JSON object
		panic(err)
	}
	for name, val := range settings {
		obj[name] = val
	}
	enc, err = json.Marshal(obj)
	if err != nil {
		// this shouldn't be reachable, as both obj comes from json.Unmarshal, and the new values are either strings from -setstr or from json.Unmarshal of -setjson values
		panic(err)
	}

	// Parse the new JSON, which incidentally gives us validation of the new properties by the jwk.Key.UnmarshalJSON method.
	keyUpd, err := jwk.ParseKey(enc)
	if err != nil {
		return err
	}
	// Write the properties back to the original key, possibly getting even more validation from the jwk.Key.Set method
	for name := range settings {
		value, _ := keyUpd.Get(name)
		if err = key.Set(name, value); err != nil {
			return err
		}
	}

	if err = jwk.AssignKeyID(key); err != nil {
		return err
	}
	return set.AddKey(key)
}
