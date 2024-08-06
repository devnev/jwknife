package main

import (
	"context"
	"errors"
	"io"
	mathrand "math/rand"
	"net/http"
	"time"
)

type httpConf struct {
	timeout  time.Duration
	interval time.Duration
	backoff  float64
	retryFor time.Duration
	jitter   float64
}

// Hopefully sane defaults, retrying for up to a minute while backing off, with a short-ish per-request timeout of 10s as payloads should be static and small.
//
//nolint:mnd // defaults chosen as per above
var defaultHTTPConf = httpConf{
	timeout:  10 * time.Second,
	interval: time.Second,
	backoff:  1.5,
	retryFor: 60 * time.Second,
	jitter:   0.1,
}

func (c httpConf) Do(req *http.Request, accept func(*http.Response) error) (*http.Response, error) {
	client := *http.DefaultClient
	if req.URL.Scheme == "https" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// Prevent downgrades from encrypted to unencrypted requests
			if req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			//nolint:mnd // Match net/http default behaviour
			if len(via) > 10 {
				return errors.New("stopped after 10 requests")
			}
			return nil
		}
	}
	lastBefore := time.Now().Add(c.retryFor)

	var lastErr error
	for wait := false; ; wait = true {
		if wait && c.interval != 0 {
			if c.retryFor == 0 {
				return nil, lastErr
			}
			if time.Now().Add(c.interval).After(lastBefore) {
				return nil, lastErr
			}
			interval := c.interval
			if c.jitter > 0 { // avoid any floating point hocus-pocus if there's no jitter
				// pick a jitter multiplier between [1, 1+jitter]
				jitter := mathrand.Float64()*c.jitter + 1 //nolint:gosec // non-crypto rand for jitter is not a security concern
				interval = time.Duration(c.interval.Seconds() * jitter * float64(time.Second))
			}
			time.Sleep(interval)
			if c.backoff > 1.0 {
				c.interval = time.Duration(c.interval.Seconds() * c.backoff * float64(time.Second))
			}
		}

		ctx := context.Background()
		var cancel context.CancelFunc = func() {}
		if c.timeout != 0 {
			ctx, cancel = context.WithTimeout(ctx, c.timeout)
		}
		req = req.WithContext(ctx)

		resp, err := client.Do(req)
		cancel()

		if err != nil {
			if withTemporary, ok := err.(interface{ Temporary() bool }); ok && withTemporary.Temporary() {
				lastErr = err
				continue
			}
			return nil, err
		}

		if err = accept(resp); err != nil {
			go func() {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}()
			lastErr = err
			continue
		}

		return resp, nil
	}
}
