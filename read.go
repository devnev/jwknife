package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

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
