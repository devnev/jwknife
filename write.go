package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var writeSyntax = strings.TrimSpace(`
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-path.mode=mode] [-path.mkdir=mode] [-url=url] [-url.post] [-url.put] [-url.allow-plaintext] [-url.timeout=duration] [-url.retry.interval=duration] [-url.retry.backoff=float] [-url.retry.end=duration] [-url.retry.jitter=float]
`)

var writeSummary = strings.TrimSpace(`
Write the JWK set.

The set can be written to either a path or a URL. The supported URL schemes are http and https, but http is only enabled when the -allow-plaintext flag is set. By default, or if -pubkey is given, only the public keys are written. Specify -fullkey to write each key in its entirety. By default, or if -jwks is given, the keys are written as a JWK set. Specify -pem to write the keys as a series of PEM blocks. If a path is specified, the file mode defaults to octal 0400. If a url is specified, the request method defaults to PUT. Specify -post to use a POST request.
`)

var writeFlags = strings.TrimSpace(`
-pubkey                      Write public key forms of each key.
-fullkey                     Write the full key for each key.
-jwks                        Write the keys as a JWK set.
-pem                         Write the keys as a series of PEM blocks.
-path=path                   Write the keys to a file at the given path.
-path.mode=mode              The permission mode of the file when a path is given.
-path.mkdir=mode             Create missing parent directories with the given permission mode.
-url=url                     Write the file to the given URL.
-url.post                    When a HTTP(S) URL is given, make a POST request.
-url.put                     When a HTTP(S) URL is given, make a PUT request.
-url.allow-plaintext         Allow plaintext traffic when writing the file using a request.
-url.timeout=duration        Timeout for a remote read. Default is 10s.
-url.retry.interval=duration Interval after a failed remote read before retrying. Default is 1s.
-url.retry.backoff=float     Multiplier applied to the interval after each attempt. Default is 1.5.
-url.retry.end=duration      No further attempts are started if the elapsed time since the first
                             attempt exceeds this duration. Default is 1m.
-url.retry.jitter=float      Randomised addition to each interval before waiting, as a proportion
                             of the interval. Defaults to 0.1.
`)

func handleWrite(args []string, set jwk.Set) error {
	var (
		writeflags = flagset{}
		pubkey     = addNoValueFlag(writeflags, "pubkey")
		fullkey    = addNoValueFlag(writeflags, "fullkey")
		jwks       = addNoValueFlag(writeflags, "jwks")
		pem        = addNoValueFlag(writeflags, "pem")
		path       = addUnparsedFlag(writeflags, "path")
		mode       = addValueFlag[uint32](writeflags, "path.mode", func(value string) (uint32, error) {
			parsed, err := strconv.ParseUint(value, 8, 32)
			if err != nil {
				return 0, err
			}
			if (parsed & ^uint64(os.ModePerm)) != 0 {
				return 0, errors.New("invalid mode")
			}
			return uint32(parsed), nil
		})
		mkdir = addValueFlag[uint32](writeflags, "path.mkdir", func(value string) (uint32, error) {
			parsed, err := strconv.ParseUint(value, 8, 32)
			if err != nil {
				return 0, err
			}
			if (parsed & ^uint64(os.ModePerm)) != 0 {
				return 0, errors.New("invalid mode")
			}
			return uint32(parsed), nil
		})
		url       = addValueFlag[*neturl.URL](writeflags, "url", neturl.Parse)
		post      = addNoValueFlag(writeflags, "url.post")
		put       = addNoValueFlag(writeflags, "url.put")
		plaintext = addNoValueFlag(writeflags, "url.allow-plaintext")
		timeout   = addValueFlag[time.Duration](writeflags, "url.timeout", parseNonNegativeDuration)
		interval  = addValueFlag[time.Duration](writeflags, "url.retry.interval", parseNonNegativeDuration)
		backoff   = addValueFlag[float64](writeflags, "url.retry.backoff", parseMultiplier)
		retryEnd  = addValueFlag[time.Duration](writeflags, "url.retry.end", parseNonNegativeDuration)
		jitter    = addValueFlag[float64](writeflags, "url.retry.jitter", parseNonNegativeFloat)
	)

	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimPrefix(arg[1:], "-"), "=")
		flag := writeflags[name]
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
	if err := oneOf(true, pubkey.Iface(), fullkey.Iface()); err != nil {
		return err
	} else if !fullkey.IsSet {
		// Set default to avoid bugs
		pubkey.IsSet = true
	}
	if err := oneOf(false, url.Iface(), path.Iface()); err != nil {
		return err
	}
	for name, flag := range writeflags {
		if strings.HasPrefix(name, "url.") {
			if err := oneOf(true, path.Iface(), flag); err != nil {
				return err
			}
		}
		if strings.HasPrefix(name, "path.") {
			if err := oneOf(true, url.Iface(), flag); err != nil {
				return err
			}
		}
	}
	if err := oneOf(true, post.Iface(), put.Iface()); err != nil {
		return err
	}

	encode := func() (string, error) {
		switch pem.IsSet {
		case true:
			var builder strings.Builder
			keys := set.Keys(context.Background())
			for keys.Next(context.Background()) {
				//nolint:forcetypeassert // It would be a bug if iterating over keys didn't give us a jwk.Key
				var key = keys.Pair().Value.(jwk.Key)
				if pubkey.IsSet {
					var err error
					if key, err = key.PublicKey(); err != nil {
						return "", err
					}
				}
				b, err := jwk.EncodePEM(key)
				if err != nil {
					return "", err
				}
				_, _ = builder.Write(b)
			}
			return builder.String(), nil
		case false:
			if pubkey.IsSet {
				pubset := jwk.NewSet()
				keys := set.Keys(context.Background())
				for keys.Next(context.Background()) {
					//nolint:forcetypeassert // It would be a bug if iterating over keys didn't give us a jwk.Key
					var key = keys.Pair().Value.(jwk.Key)
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
		default:
			panic("unreachable")
		}
	}

	if path.IsSet {
		encoded, err := encode()
		if err != nil {
			return err
		}
		var filemode os.FileMode = 0400
		if mode.IsSet {
			filemode = os.FileMode(mode.Value)
		}
		err = os.WriteFile(path.Value, []byte(encoded), filemode)
		if os.IsNotExist(err) && mkdir.IsSet {
			if err = os.MkdirAll(filepath.Base(path.Value), os.FileMode(mkdir.Value)); err != nil {
				return err
			}
			err = os.WriteFile(path.Value, []byte(encoded), filemode)
		}
		return err
	}

	if url.IsSet {
		switch {
		case url.Value.Scheme == "https":
		case plaintext.IsSet && url.Value.Scheme == "http":
		default:
			return errors.New("unsupported scheme for --url")
		}

		encoded, err := encode()
		if err != nil {
			return err
		}
		var method = http.MethodPut
		if post.IsSet {
			method = http.MethodPost
		}

		reqConf := defaultHTTPConf
		assignIfSet(timeout, &reqConf.timeout)
		assignIfSet(interval, &reqConf.interval)
		assignIfSet(backoff, &reqConf.backoff)
		assignIfSet(retryEnd, &reqConf.retryFor)
		assignIfSet(jitter, &reqConf.jitter)

		return writeToURL(encoded, method, url.Value, reqConf)
	}

	panic("unreachable")
}

func writeToURL(content string, method string, url *neturl.URL, conf httpConf) error {
	//nolint:noctx // the retrier manages the timeout
	req, err := http.NewRequest(method, url.String(), strings.NewReader(content))
	if err != nil {
		// should be unreachable
		panic(err.Error())
	}

	resp, err := conf.Do(req, func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return errors.New("URl returned non-OK status")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = resp.Body.Close(); err != nil {
		return err
	}
	return nil
}
