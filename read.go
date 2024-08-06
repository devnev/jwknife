package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var readSyntax = strings.TrimSpace(`
read [-jwks] [-pem] [-allow-plaintext] [-path=path] [-url=url] [-schemes=scheme[,...]]
`)

var readSummary = strings.TrimSpace(`
Append keys to the JWK set.

The source may be given using a path or a URL. The supported URL schemes are file, http and https, but http is only enabled when the -allow-plaintext flag is set. To further restrict the allowed schemes, use the --scheme flag.

If -pem is given, the ssource must be a series of one or more PEM blocks. Otherwise (with -jwks given, or neither -jwks nor -pem), the source must be either a JWK or a JWK set.
`)

var readFlags = strings.TrimSpace(`
-jwks                 The source must be a JWK or JWK set.
-pem                  The source must be a series of PEM blocks.
-allow-plaintext      Allow plaintext traffic during retrieval of the URL.
-path=path            The path of the source file.
-url=url              The url of the source. Supported schemes are file, http and https.
-schemes=scheme[,...] The schemes to allow. Defaults to all supported if not specified.
`)

var plaintextSchemes = []string{"http"}
var nonPlaintextSchemes = []string{"file", "https"}
var supportedSchemes = append(nonPlaintextSchemes, plaintextSchemes...)

func handleRead(args []string, set jwk.Set) error {
	var (
		jwks      bool
		pem       bool
		plaintext bool
		path      *string
		url       *string
		schemes   *[]string
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
		case "allow-plaintext":
			if plaintext {
				return errors.New("duplicate flag --allow-plaintext")
			}
			if found {
				return errors.New("--allow-plaintext does not take a value")
			}
			plaintext = true
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
			if url != nil {
				return errors.New("duplicate flag --path")
			}
			if value == "" {
				return errors.New("missing or empty value for --url")
			}
			url = new(string)
			*url = value
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
				if !slices.Contains(supportedSchemes, scheme) {
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
		//nolint:ineffassign // Make the values consistent even though its not used (yet)
		jwks = true
	}

	if url == nil && path == nil {
		return errors.New("must specify either --path or --url")
	}
	if url != nil && path != nil {
		return errors.New("cannot specify both --path and --url")
	}

	if url != nil {
		if schemes != nil && !plaintext {
			for _, scheme := range *schemes {
				if slices.Contains(plaintextSchemes, scheme) {
					return errors.New("plaintext scheme forbidden without -allow-plaintext")
				}
			}
		}
		if schemes == nil {
			schemes = new([]string)
			if plaintext {
				*schemes = supportedSchemes
			} else {
				*schemes = nonPlaintextSchemes
			}
		}
		parsed, err := neturl.Parse(*url)
		if err != nil {
			return err
		}
		if !slices.Contains(*schemes, parsed.Scheme) {
			return errors.New("blocked url scheme")
		}
		var kind = kindJWK
		if pem {
			kind = kindPEM
		}
		return readFromURL(parsed, kind, set)
	}

	if path != nil {
		if plaintext {
			return errors.New("can only specify --insecure with --url")
		}
		if schemes != nil {
			return errors.New("can only specify --schemes with --url")
		}
		var kind = kindJWK
		if pem {
			kind = kindPEM
		}
		return readFromPath(*path, kind, set)
	}

	panic("unreachable")
}

func readFromPath(arg string, kind contentKind, set jwk.Set) error {
	contents, err := os.ReadFile(arg)
	if err != nil {
		return err
	}
	return parseContents(contents, kind, set)
}

func readFromURL(from *neturl.URL, kind contentKind, set jwk.Set) error {
	if from.Scheme == "file" {
		if from.Opaque != "" {
			path, err := neturl.PathUnescape(from.Opaque)
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
		//nolint:noctx // TODO: introduce timeout
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

type contentKind string

const (
	kindPEM contentKind = "pem"
	kindJWK contentKind = "jwk"
)

func parseContents(contents []byte, kind contentKind, set jwk.Set) error {
	read, err := jwk.Parse(contents, jwk.WithPEM(kind == kindPEM))
	if err != nil {
		return err
	}
	iter := read.Keys(context.Background())
	for iter.Next(context.Background()) {
		//nolint:forcetypeassert // It would be a bug if iterating over keys didn't give us a jwk.Key
		if err = (set).AddKey(iter.Pair().Value.(jwk.Key)); err != nil {
			return err
		}
	}
	return nil
}
