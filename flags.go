package main

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

func addNoValueFlag(fs flagset, name string) *valflag[novalue] {
	flag := &valflag[novalue]{Name: name}
	fs.addFlag(name, flag.Iface())
	return flag
}

func addValueFlag[T any](fs flagset, name string, parse func(string) (T, error)) *valflag[T] {
	flag := &valflag[T]{Name: name, Parse: parse}
	fs.addFlag(name, flag.Iface())
	return flag
}

func addUnparsedFlag(fs flagset, name string) *valflag[string] {
	return addValueFlag[string](fs, name, func(v string) (string, error) { return v, nil })
}

//nolint:unused // Worth keeping? eh
func addSliceFlag[T any](fs flagset, name string, parse func(string) (T, error)) *valflag[[]T] {
	flag := &valflag[[]T]{
		Name: name,
		Parse: func(s string) ([]T, error) {
			val, err := parse(s)
			if err != nil {
				return nil, err
			}
			return []T{val}, nil
		},
		Update: func(ss []T, s string) ([]T, error) {
			val, err := parse(s)
			if err != nil {
				return ss, err
			}
			return append(ss, val), nil
		},
	}
	fs.addFlag(name, flag.Iface())
	return flag
}

//nolint:unused // Worth keeping? eh
func addUnparsedSliceFlag(fs flagset, name string) *valflag[[]string] {
	return addSliceFlag[string](fs, name, func(s string) (string, error) {
		return s, nil
	})
}

//nolint:unparam // return value not currently used but might as well be consistent
func addExternalFlag(fs flagset, name string, handle func(val string) error) *valflag[struct{}] {
	flag := &valflag[struct{}]{
		Name: name,
		Parse: func(s string) (struct{}, error) {
			return struct{}{}, handle(s)
		},
		Update: func(_ struct{}, s string) (struct{}, error) {
			return struct{}{}, handle(s)
		},
	}
	fs.addFlag(name, flag.Iface())
	return flag
}

type novalue struct{}

type valflag[T any] struct {
	Name   string
	IsSet  bool
	Value  T
	Parse  func(string) (T, error)
	Update func(T, string) (T, error)
}

func (f *valflag[T]) Set() error {
	if f.IsSet && f.Update == nil {
		return errors.New("duplicate flag --" + f.Name)
	}
	f.IsSet = true
	if any(f.Value) != any(novalue{}) {
		return errors.New("missing value for --" + f.Name)
	}
	return nil
}

func (f *valflag[T]) SetValue(value string) error {
	update := f.IsSet
	f.IsSet = true
	var err error
	switch {
	case any(f.Value) == any(novalue{}):
		err = errors.New("--" + f.Name + " does not take a value")
	case value == "":
		err = errors.New("value for --" + f.Name + " must not be empty")
	case update && f.Update != nil:
		f.Value, err = f.Update(f.Value, value)
	case update:
		err = errors.New("duplicate flag --" + f.Name)
	default:
		f.Value, err = f.Parse(value)
	}
	return err
}

func (f *valflag[T]) Iface() flag { //nolint:ireturn // interface return is intentional here
	return valflagwrapper[T]{flag: f}
}

type flag interface {
	Name() string
	IsSet() bool
	Set() error
	SetValue(value string) error
}

func oneOf(noneOK bool, flags ...flag) error {
	var count int
	for _, f := range flags {
		if f.IsSet() {
			count++
		}
	}
	if count == 1 {
		return nil
	}
	if noneOK && count == 0 {
		return nil
	}

	names := make([]string, 0, len(flags))
	for _, f := range flags {
		names = append(names, "--"+f.Name())
	}
	lastidx := len(names) - 1
	allbut, last := names[:lastidx], names[lastidx]
	if count == 0 {
		if len(flags) == 2 { //nolint:mnd // magic value is for nicer output
			return errors.New("must specify one of " + strings.Join(names, " or "))
		}
		return errors.New("must specify one of " + strings.Join(allbut, ", ") + ", or " + last)
	}
	if len(flags) == 2 { //nolint:mnd // magic value is for nicer output
		return errors.New("cannot specify both " + strings.Join(names, " and "))
	}
	return errors.New("cannot specify multiple of " + strings.Join(allbut, ", ") + ", and " + last)
}

func assignIfSet[T any](f *valflag[T], dst *T) {
	if f.IsSet {
		*dst = f.Value
	}
}

type valflagwrapper[T any] struct {
	flag *valflag[T]
}

func (f valflagwrapper[T]) Name() string {
	return f.flag.Name
}

func (f valflagwrapper[T]) IsSet() bool {
	return f.flag.IsSet
}

func (f valflagwrapper[T]) Set() error {
	return f.flag.Set()
}

func (f valflagwrapper[T]) SetValue(v string) error {
	return f.flag.SetValue(v)
}

type flagset map[string]flag

func (s flagset) addFlag(name string, f flag) {
	if s[name] != nil {
		panic("duplicate flag --" + name)
	}
	s[name] = f
}

func parseNonNegativeDuration(value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, errors.New("invalid negative duration")
	}
	return d, nil
}

func parseNonNegativeFloat(value string) (float64, error) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if f < 0 {
		return 0, errors.New("value must be non-negative")
	}
	return f, nil
}

func parseMultiplier(value string) (float64, error) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if f < 1 {
		return 0, errors.New("must be a value of at least 1")
	}
	return f, nil
}
