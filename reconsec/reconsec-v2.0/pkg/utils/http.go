package utils

import (
	"net/http"
	"time"
)

func HTTPClient(timeoutSec int) *http.Client {
	if timeoutSec <= 0 { timeoutSec = 15 }
	return &http.Client{ Timeout: time.Duration(timeoutSec) * time.Second }
}
