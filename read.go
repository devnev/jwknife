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
		readflags = flagset{}
		jwks      = addNoValueFlag(readflags, "jwks")
		pem       = addNoValueFlag(readflags, "pem")
		plaintext = addNoValueFlag(readflags, "allow-plaintext")
		path      = addUnparsedFlag(readflags, "path")
		url       = addValueFlag[*neturl.URL](readflags, "url", neturl.Parse)
		schemes   = addValueFlag[[]string](readflags, "schemes", func(v string) ([]string, error) {
			split := strings.Split(v, ",")
			for _, scheme := range split {
				if !slices.Contains(supportedSchemes, scheme) {
					return nil, errors.New("unsupported scheme")
				}
			}
			return split, nil
		})
	)

	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimPrefix(arg[1:], "-"), "=")
		flag := readflags[name]
		var err error
		switch {
		case flag == nil:
			err = errors.New("unknown flag --" + name)
		case !found:
			err = flag.Set()
		default:
			err = flag.SetValue(value)
		}
		if err != nil {
			return err
		}
	}

	if err := oneOf(true, jwks.Iface(), pem.Iface()); err != nil {
		return err
	} else if !pem.IsSet {
		// Set default to avoid bugs
		jwks.IsSet = true
	}
	if err := oneOf(false, url.Iface(), path.Iface()); err != nil {
		return err
	}
	if err := oneOf(true, path.Iface(), plaintext.Iface()); err != nil {
		return err
	}
	if err := oneOf(true, path.Iface(), schemes.Iface()); err != nil {
		return err
	}
	if schemes.IsSet && !plaintext.IsSet {
		for _, scheme := range schemes.Value {
			if slices.Contains(plaintextSchemes, scheme) {
				return errors.New("plaintext scheme forbidden without -allow-plaintext")
			}
		}
	}
	if !schemes.IsSet {
		if plaintext.IsSet {
			schemes.Value = supportedSchemes
		} else {
			schemes.Value = nonPlaintextSchemes
		}
	}

	if url.IsSet {
		if !slices.Contains(schemes.Value, url.Value.Scheme) {
			return errors.New("blocked url scheme")
		}
		var kind = kindJWK
		if pem.IsSet {
			kind = kindPEM
		}
		return readFromURL(url.Value, kind, set)
	}

	if path.IsSet {
		var kind = kindJWK
		if pem.IsSet {
			kind = kindPEM
		}
		return readFromPath(path.Value, kind, set)
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
