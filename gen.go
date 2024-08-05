package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

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
