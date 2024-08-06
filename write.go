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

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var writeSyntax = strings.TrimSpace(`
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-mode=octal] [-mkdir=octal] [-url=url] [-post] [-put] [-allow-plaintext]
`)

var writeSummary = strings.TrimSpace(`
Write the JWK set.

The set can be written to either a path or a URL. The supported URL schemes are http and https, but http is only enabled when the -allow-plaintext flag is set. By default, or if -pubkey is given, only the public keys are written. Specify -fullkey to write each key in its entirety. By default, or if -jwks is given, the keys are written as a JWK set. Specify -pem to write the keys as a series of PEM blocks. If a path is specified, the file mode defaults to octal 0400. If a url is specified, the request method defaults to PUT. Specify -post to use a POST request.
`)

var writeFlags = strings.TrimSpace(`
-pubkey          Write public key forms of each key.
-fullkey         Write the full key for each key.
-jwks            Write the keys as a JWK set.
-pem             Write the keys as a series of PEM blocks.
-path=path       Write the keys to a file at the given path.
-mode=mode       The permission mode of the file when a path is given.
-mkdir=mode      Create missing parent directories with the given permission mode.
-url=url         Write the file to the given URL.
-post            When a HTTP(S) URL is given, make a POST request.
-put             When a HTTP(S) URL is given, make a PUT request.
-allow-plaintext Allow plaintext traffic when writing the file using a request.
`)

func handleWrite(args []string, set jwk.Set) error {
	var (
		pubkey    bool
		fullkey   bool
		jwks      bool
		pem       bool
		path      *string
		mode      *uint32
		mkdir     *uint32
		post      bool
		put       bool
		url       *neturl.URL
		plaintext bool
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
			if (parsed & ^uint64(os.ModePerm)) != 0 {
				return errors.New("invalid mode")
			}
			mode = new(uint32)
			*mode = uint32(parsed)
		case "mkdir":
			if mkdir != nil {
				return errors.New("duplicate flag --mkdir")
			}
			if value == "" {
				return errors.New("missing or empty value for --mkdir")
			}
			parsed, err := strconv.ParseUint(value, 8, 32)
			if err != nil {
				return err
			}
			if (parsed & ^uint64(os.ModePerm)) != 0 {
				return errors.New("invalid mkdir mode")
			}
			mkdir = new(uint32)
			*mkdir = uint32(parsed)
		case "url":
			if url != nil {
				return errors.New("duplicate flag --url")
			}
			if value == "" {
				return errors.New("missing or empty value for --url")
			}
			parsed, err := neturl.Parse(value)
			if err != nil {
				return err
			}
			url = parsed
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
		case "allow-plaintext":
			if plaintext {
				return errors.New("duplicate flag --allow-plaintext")
			}
			if found {
				return errors.New("--allow-plaintext does not take a value")
			}
			plaintext = true
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

	if pubkey && fullkey {
		return errors.New("cannot specify both --pubkey and --fullkey")
	} else if !fullkey {
		pubkey = true
	}

	encode := func() (string, error) {
		switch pem {
		case true:
			var builder strings.Builder
			keys := set.Keys(context.Background())
			for keys.Next(context.Background()) {
				//nolint:forcetypeassert // It would be a bug if iterating over keys didn't give us a jwk.Key
				var key = keys.Pair().Value.(jwk.Key)
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
				_, _ = builder.Write(b)
			}
			return builder.String(), nil
		case false:
			if pubkey {
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

	if url == nil && path == nil {
		return errors.New("must specify either --path or --url")
	}
	if url != nil && path != nil {
		return errors.New("cannot specify both --path and --url")
	}

	if path != nil {
		if post {
			return errors.New("cannot specify both --path and --post")
		}
		if put {
			return errors.New("cannot specify both --path and --put")
		}
		if plaintext {
			return errors.New("cannot specify both --path and --allow-plaintext")
		}

		encoded, err := encode()
		if err != nil {
			return err
		}
		var filemode os.FileMode = 0400
		if mode != nil {
			filemode = os.FileMode(*mode)
		}
		err = os.WriteFile(*path, []byte(encoded), filemode)
		if os.IsNotExist(err) && mkdir != nil {
			if err = os.MkdirAll(filepath.Base(*path), os.FileMode(*mkdir)); err != nil {
				return err
			}
			err = os.WriteFile(*path, []byte(encoded), filemode)
		}
		return err
	}

	if url != nil {
		if mode != nil {
			return errors.New("cannot specify both --url and --mode")
		}
		if mkdir != nil {
			return errors.New("cannot specify both --url and --mkdir")
		}
		if post && put {
			return errors.New("cannot specify both --post and --put")
		}
		switch {
		case url.Scheme == "https":
		case plaintext && url.Scheme == "http":
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
		//nolint:noctx // TODO: introduce timeout
		req, err := http.NewRequest(method, url.String(), strings.NewReader(encoded))
		if err != nil {
			// should not be reachable
			panic(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		if err = resp.Body.Close(); err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return errors.New("received non-OK response")
		}
		return nil
	}

	panic("unreachable")
}
