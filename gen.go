package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
)

var genSyntax = strings.TrimSpace(`
gen [-rsa=bits] [-ec] [-okp] [-setstr=key=str] [-setjson=key=json]
`)

var genSummary = strings.TrimSpace(`
Generate and append a key to the JWK set.

Key generation takes its parameters from the key's properties where possible. Specifically, EC and OKP keys use the "alg" and/or "crv" fields to determine which elliptic curve to use.

The private key is added to the JWK set during generation. To get just the public key, use the corresponding flags on the write command when writing keys.

Properties of the key are set using -setstr or -setjson. The "kty" property cannot be modified. Minimal validation is applied to properties; standard JWK properties must have the correct primitive type.
`)

var genFlags = strings.TrimSpace(`
-rsa=bits         Generate an RSA key with the given bit length.
-ec               Generate an EC key.
-okp              Generate an OKP key.
-setstr=key=str   Set the given property to the (unparsed) string value.
-setjson=key=json Parse the value as JSON and set the given property to the value.
`)

func handleGen(args []string, set jwk.Set) error {
	var (
		genflags = flagset{}
		rsabits  = addValueFlag[int](genflags, "rsa", func(s string) (int, error) {
			// Being conservative, allowing only specific bit lengths
			//nolint:mnd // no point in extracting these to constants
			bits := map[string]int{
				"2048": 2048,
				"3072": 3072,
				"4096": 4096,
			}[s]
			if bits == 0 {
				return 0, errors.New("unsupported bit-length for --rsa")
			}
			return bits, nil
		})
		ec    = addNoValueFlag(genflags, "ec") //nolint:varnamelen // This is fine
		okp   = addNoValueFlag(genflags, "okp")
		props = make(map[string]any)
		_     = addExternalFlag(genflags, "setstr", func(value string) error {
			name, value, found := strings.Cut(value, "=")
			if !found {
				return errors.New("--set value must be key=value format")
			}
			if _, exists := props[value]; exists {
				return errors.New("duplicate --set key")
			}
			props[name] = value
			return nil
		})
		_ = addExternalFlag(genflags, "setjson", func(value string) error {
			name, value, found := strings.Cut(value, "=")
			if !found {
				return errors.New("--set value must be key=value format")
			}
			if _, exists := props[value]; exists {
				return errors.New("duplicate --set key")
			}
			var obj any
			if err := json.Unmarshal([]byte(value), &obj); err != nil {
				return err
			}
			props[name] = obj
			return nil
		})
	)

	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimPrefix(arg[1:], "-"), "=")
		flag := genflags[name]
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

	if err := oneOf(false, rsabits.Iface(), ec.Iface(), okp.Iface()); err != nil {
		return err
	}

	if rsabits.IsSet {
		rawKey, err := rsa.GenerateKey(rand.Reader, rsabits.Value)
		if err != nil {
			return err
		}
		return addKey(rawKey, props, set)
	}

	if ec.IsSet {
		crvval, haveCrv := props["crv"]
		if !haveCrv {
			switch props["alg"] {
			case jwa.ES256.String():
				crvval = jwa.P256.String()
			case jwa.ES384.String():
				crvval = jwa.P384.String()
			case jwa.ES512.String():
				crvval = jwa.P521.String()
			default:
				if _, ok := props["alg"]; ok {
					return errors.New("cannot infer crv from alg field, must set crv field with --setstr or --setjson for --ec")
				}
				return errors.New("must set crv or alg field with --setstr or --setjson for --ec")
			}
		}
		crv, crvIsString := crvval.(string)
		if !crvIsString {
			return errors.New("crv field must be string for --ec")
		}
		curve, haveCurve := jwk.CurveForAlgorithm(jwa.EllipticCurveAlgorithm(crv))
		if !haveCurve {
			return errors.New("curve unavailable")
		}
		if _, haveAlg := props["alg"]; !haveAlg {
			switch crv {
			case jwa.P256.String():
				props["alg"] = jwa.ES256.String()
			case jwa.P384.String():
				props["alg"] = jwa.ES384.String()
			case jwa.P521.String():
				props["alg"] = jwa.ES512.String()
			}
		}

		rawKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		return addKey(rawKey, props, set)
	}

	if okp.IsSet {
		algval, haveAlg := props["alg"]
		if haveAlg {
			alg, algIsStr := algval.(string)
			if !algIsStr {
				return errors.New("alg field must be string for --okp")
			}
			if alg != jwa.EdDSA.String() {
				return errors.New("invalid alg field value for --okp")
			}
		} else {
			props["alg"] = jwa.EdDSA.String()
		}

		crvval, haveCrv := props["crv"]
		if !haveCrv {
			return errors.New("must set crv field with --setstr or --setjson for --okp")
		}
		crv, crvIsStr := crvval.(string)
		if !crvIsStr {
			return errors.New("crv field must be string for --okp")
		}
		var rawKey any
		var err error
		switch crv {
		case jwa.Ed25519.String():
			_, rawKey, err = ed25519.GenerateKey(rand.Reader)
		case jwa.X25519.String():
			_, rawKey, err = x25519.GenerateKey(rand.Reader)
		default:
			return errors.New("curve unavailable")
		}
		if err != nil {
			return err
		}
		return addKey(rawKey, props, set)
	}

	panic("unreachable")
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
