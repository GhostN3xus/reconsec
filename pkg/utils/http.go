package utils

import "net/http"

func HTTPClient(timeoutSec int) *http.Client {
	if timeoutSec <= 0 { timeoutSec = 15 }
	return &http.Client{ Timeout: 0 }
}
