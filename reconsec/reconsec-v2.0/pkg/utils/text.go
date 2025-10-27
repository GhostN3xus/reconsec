package utils

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func SanitizeFilename(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		raw = strings.TrimPrefix(raw, "http://")
		raw = strings.TrimPrefix(raw, "https://")
	}
	raw = strings.TrimSuffix(raw, "/")
	out := make([]rune, 0, len(raw))
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r=='.' || r=='-' || r=='_' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	if len(out)==0 {
		sum := sha256.Sum256([]byte(raw))
		return fmt.Sprintf("target_%x", sum[:6])
	}
	return string(out)
}
