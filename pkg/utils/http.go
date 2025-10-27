package utils

import (
	"net/http"
	"time"
)

// HTTPClient returns an http.Client with a sane timeout.  Older code returned
// a client with Timeout=0 (meaning no timeout), which could hang forever when
// talking to unresponsive hosts.  Enforce a floor of 15 seconds so short-lived
// proof-of-concept probes and scans fail fast instead of blocking operators.
func HTTPClient(timeoutSec int) *http.Client {
	if timeoutSec <= 0 {
		timeoutSec = 15
	}

	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}
}
