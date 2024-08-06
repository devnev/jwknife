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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var readSyntax = strings.TrimSpace(`
read [-jwks] [-pem] [-path=path] [-url=url] [-url.allow-plaintext] [-url.schemes=scheme[,...]] [-url.timeout=duration] [-url.retry.interval=duration] [-url.retry.backoff=float] [-url.retry.end=duration] [-url.retry.jitter=float]
`)

var readSummary = strings.TrimSpace(`
Append keys to the JWK set.

The source may be given using a path or a URL. The supported URL schemes are file, http and https, but http is only enabled when the -allow-plaintext flag is set. To further restrict the allowed schemes, use the --scheme flag.

If -pem is given, the ssource must be a series of one or more PEM blocks. Otherwise (with -jwks given, or neither -jwks nor -pem), the source must be either a JWK or a JWK set.
`)

var readFlags = strings.TrimSpace(`
-jwks                        The source must be a JWK or JWK set.
-pem                         The source must be a series of PEM blocks.
-path=path                   The path of the source file.
-url=url                     The url of the source. Supported schemes are file, http and https.
-url.allow-plaintext         Allow plaintext traffic during retrieval of the URL.
-url.schemes=scheme[,...]    The schemes to allow. Defaults to all supported if not specified.
-url.timeout=duration        Timeout for a remote read. Default is 10s.
-url.retry.interval=duration Interval after a failed remote read before retrying. Default is 1s.
-url.retry.backoff=float     Multiplier applied to the interval after each attempt. Default is 1.5.
-url.retry.end=duration      No further attempts are started if the elapsed time since the first
                             attempt exceeds this duration. Default is 1m.
-url.retry.jitter=float      Randomised addition to each interval before waiting, as a proportion
                             of the interval. Defaults to 0.1.
`)

var plaintextSchemes = []string{"http"}
var nonPlaintextSchemes = []string{"file", "https"}
var supportedSchemes = append(nonPlaintextSchemes, plaintextSchemes...)

func handleRead(args []string, set jwk.Set) error {
	var (
		readflags = flagset{}
		jwks      = addNoValueFlag(readflags, "jwks")
		pem       = addNoValueFlag(readflags, "pem")
		path      = addUnparsedFlag(readflags, "path")
		url       = addValueFlag[*neturl.URL](readflags, "url", neturl.Parse)
		schemes   = addValueFlag[[]string](readflags, "url.schemes", func(v string) ([]string, error) {
			split := strings.Split(v, ",")
			for _, scheme := range split {
				if !slices.Contains(supportedSchemes, scheme) {
					return nil, errors.New("unsupported scheme")
				}
			}
			return split, nil
		})
		plaintext = addNoValueFlag(readflags, "url.allow-plaintext")
		timeout   = addValueFlag[time.Duration](readflags, "url.timeout", parseNonNegativeDuration)
		interval  = addValueFlag[time.Duration](readflags, "url.retry.interval", parseNonNegativeDuration)
		backoff   = addValueFlag[float64](readflags, "url.retry.backoff", parseMultiplier)
		retryEnd  = addValueFlag[time.Duration](readflags, "url.retry.end", parseNonNegativeDuration)
		jitter    = addValueFlag[float64](readflags, "url.retry.jitter", parseNonNegativeFloat)
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
	for name, flag := range readflags {
		if strings.HasPrefix(name, "url.") {
			if err := oneOf(true, path.Iface(), flag); err != nil {
				return err
			}
		}
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

		retry := defaultRetryConf
		assignIfSet(timeout, &retry.timeout)
		assignIfSet(interval, &retry.interval)
		assignIfSet(backoff, &retry.backoff)
		assignIfSet(retryEnd, &retry.retryFor)
		assignIfSet(jitter, &retry.jitter)

		var kind = kindJWK
		if pem.IsSet {
			kind = kindPEM
		}

		return readFromURL(url.Value, retry, kind, set)
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

func readFromURL(from *neturl.URL, retry retryConf, kind contentKind, set jwk.Set) error {
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
		//nolint:noctx // the retrier manages the timeout
		req, err := http.NewRequest(http.MethodGet, from.String(), nil)
		if err != nil {
			// should be unreachable
			panic(err.Error())
		}
		resp, err := retry.Do(req, func(resp *http.Response) error {
			if resp.StatusCode != http.StatusOK {
				return errors.New("URl returned non-OK status")
			}
			return nil
		})
		if err != nil {
			return err
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
