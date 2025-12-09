package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "ApiKey 12345")

	key, err := GetAPIKey(h)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if key != "12345" {
		t.Fatalf("expected API key '12345', got '%s'", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	h := http.Header{}

	_, err := GetAPIKey(h)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer 12345")

	_, err := GetAPIKey(h)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed header error, got '%v'", err)
	}
}
