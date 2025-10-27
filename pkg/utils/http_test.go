package utils

import (
	"testing"
	"time"
)

func TestHTTPClientTimeout(t *testing.T) {
	c := HTTPClient(5)
	if expected := 5 * time.Second; c.Timeout != expected {
		t.Fatalf("expected timeout %s, got %s", expected, c.Timeout)
	}

	c = HTTPClient(0)
	if expected := 15 * time.Second; c.Timeout != expected {
		t.Fatalf("expected default timeout %s, got %s", expected, c.Timeout)
	}
}
