package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
)

const (
	mockJwksServerlistenAddr = ":9091"
	mockJwksServerPath       = "/auth/realm/key/path"
)

var (
	testPrivateKey *ecdsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error

	testPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc(mockJwksServerPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "application/json")

		json.NewEncoder(w).Encode(publicKeyJson{
			CurveParams: testPrivateKey.PublicKey.Params(),
			MyX:         testPrivateKey.PublicKey.X,
			MyY:         testPrivateKey.PublicKey.Y,
		})
	})

	go func() {
		http.ListenAndServe(mockJwksServerlistenAddr, mux)
	}()

	m.Run()
}
