package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey secret123")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "secret123" {
		t.Fatalf("expected key %q, got %q", "secret123", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	key, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKey_EmptyHeaderValue(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "")

	key, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKey_WrongScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer sometoken")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed header error, got %v", err)
	}
}

func TestGetAPIKey_MissingKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed header error, got %v", err)
	}
}

func TestGetAPIKey_EmptyKeyAfterApiKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey ")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}
