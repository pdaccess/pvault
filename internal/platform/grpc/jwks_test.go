package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseECKeyFromJWKS(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default",
				"x":   x,
				"y":   y,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	jwks := NewJWKS(server.URL)
	key, err := jwks.getKey("default", "ES256")
	if err != nil {
		t.Fatalf("getKey failed: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	if ecKey.X.Cmp(privateKey.PublicKey.X) != 0 {
		t.Error("X coordinates don't match")
	}
	if ecKey.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		t.Error("Y coordinates don't match")
	}
}

func TestParseRSAKeyFromJWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	eBytes := make([]byte, (privateKey.PublicKey.E+7)/8)
	for i := len(eBytes) - 1; i >= 0; i-- {
		eBytes[i] = byte(privateKey.PublicKey.E >> uint((len(eBytes)-1-i)*8))
	}
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "rsa-key",
				"n":   n,
				"e":   e,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	jwks := NewJWKS(server.URL)
	key, err := jwks.getKey("rsa-key", "RS256")
	if err != nil {
		t.Fatalf("getKey failed: %v", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}

	if rsaKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Error("N values don't match")
	}
	if rsaKey.E != privateKey.PublicKey.E {
		t.Errorf("E values don't match: got %d, want %d", rsaKey.E, privateKey.PublicKey.E)
	}
}

func TestValidateECSignedToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default",
				"x":   x,
				"y":   y,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	validator := NewJWKSValidator(server.URL, "default", 5*time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":      "user123",
		"user_uid": "user123",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = validator.Validate(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	claims, err := validator.Claims(tokenString)
	if err != nil {
		t.Fatalf("Claims failed: %v", err)
	}

	if claims["sub"] != "user123" {
		t.Errorf("expected sub=user123, got %v", claims["sub"])
	}
}

func TestValidateExpiredToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default",
				"x":   x,
				"y":   y,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	validator := NewJWKSValidator(server.URL, "default", 5*time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = validator.Validate(context.Background(), tokenString)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestValidateTokenWrongKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default",
				"x":   x,
				"y":   y,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	validator := NewJWKSValidator(server.URL, "default", 5*time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(wrongKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = validator.Validate(context.Background(), tokenString)
	if err == nil {
		t.Fatal("expected error for token signed with wrong key, got nil")
	}
}

func TestValidateRSASignedToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	eBytes := make([]byte, (privateKey.PublicKey.E+7)/8)
	for i := len(eBytes) - 1; i >= 0; i-- {
		eBytes[i] = byte(privateKey.PublicKey.E >> uint((len(eBytes)-1-i)*8))
	}
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "rsa-key",
				"n":   n,
				"e":   e,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	validator := NewJWKSValidator(server.URL, "rsa-key", 5*time.Minute)
	validator.alg = "RS256"

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = validator.Validate(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	claims, err := validator.Claims(tokenString)
	if err != nil {
		t.Fatalf("Claims failed: %v", err)
	}

	if claims["sub"] != "user123" {
		t.Errorf("expected sub=user123, got %v", claims["sub"])
	}
}

func TestKeyNotFoundInJWKS(t *testing.T) {
	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "other-key",
				"x":   "abc",
				"y":   "def",
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	jwks := NewJWKS(server.URL)
	_, err := jwks.getKey("default", "ES256")
	if err == nil {
		t.Fatal("expected error when key not found, got nil")
	}
}

func TestJWKSRefresh(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	jwksData := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default",
				"x":   x,
				"y":   y,
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwksData)

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	validator := NewJWKSValidator(server.URL, "default", 100*time.Millisecond)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(privateKey)

	err = validator.Validate(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	validator.refresh()
	if requestCount < 2 {
		t.Errorf("expected at least 2 requests, got %d", requestCount)
	}
}
