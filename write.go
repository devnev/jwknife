package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

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
