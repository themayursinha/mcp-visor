package vault_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/vault"
)

func setupMockVault(t *testing.T, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) string {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false})
	})

	mux.HandleFunc("/v1/transit/keys/test-key", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"keys": map[string]any{
					"1": map[string]any{
						"public_key": base64.StdEncoding.EncodeToString(pubKey),
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/transit/sign/test-key", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		input, _ := base64.StdEncoding.DecodeString(body["input"])
		sig := ed25519.Sign(privKey, input)
		vaultSig := fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString(sig))
		resp := map[string]any{
			"data": map[string]any{"signature": vaultSig},
		}
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/transit/verify/test-key", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		input, _ := base64.StdEncoding.DecodeString(body["input"])
		sig := body["signature"]
		var rawSig []byte
		prefix := "vault:v1:"
		if len(sig) > len(prefix) && sig[:len(prefix)] == prefix {
			rawSig, _ = base64.StdEncoding.DecodeString(sig[len(prefix):])
		}
		valid := ed25519.Verify(pubKey, input, rawSig)
		resp := map[string]any{
			"data": map[string]any{"valid": valid},
		}
		json.NewEncoder(w).Encode(resp)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := fmt.Sprintf("http://%s", listener.Addr().String())

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { srv.Close() })

	return addr
}

func TestVaultHealth(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr := setupMockVault(t, priv, pub)

	client, err := vault.NewClient(vault.Config{
		Addr:  addr,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("health check: %v", err)
	}
}

func TestTransitSignerSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr := setupMockVault(t, priv, pub)

	client, err := vault.NewClient(vault.Config{
		Addr:  addr,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	s, err := vault.NewTransitSigner(client, "test-key")
	if err != nil {
		t.Fatalf("new transit signer: %v", err)
	}

	data := []byte("approval-payload-to-sign")
	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !ed25519.Verify(pub, data, sig) {
		t.Fatal("signature verification failed")
	}

	if s.Algorithm() != "ed25519-vault-transit" {
		t.Errorf("unexpected algorithm: %s", s.Algorithm())
	}
}

func TestTransitSignerPublicKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr := setupMockVault(t, priv, pub)

	client, _ := vault.NewClient(vault.Config{
		Addr:  addr,
		Token: "test-token",
	})

	s, err := vault.NewTransitSigner(client, "test-key")
	if err != nil {
		t.Fatalf("new transit signer: %v", err)
	}

	gotPub := s.PublicKey().(ed25519.PublicKey)
	if !gotPub.Equal(pub) {
		t.Fatal("public key mismatch")
	}
}

func TestTransitVerifierVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr := setupMockVault(t, priv, pub)

	client, _ := vault.NewClient(vault.Config{
		Addr:  addr,
		Token: "test-token",
	})

	v, err := vault.NewTransitVerifier(client, "test-key")
	if err != nil {
		t.Fatalf("new transit verifier: %v", err)
	}

	data := []byte("data-to-verify")
	sig := ed25519.Sign(priv, data)

	if err := v.Verify(data, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTransitVerifierVerifyBadSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr := setupMockVault(t, priv, pub)

	client, _ := vault.NewClient(vault.Config{
		Addr:  addr,
		Token: "test-token",
	})

	v, err := vault.NewTransitVerifier(client, "test-key")
	if err != nil {
		t.Fatalf("new transit verifier: %v", err)
	}

	data := []byte("real-payload")
	badSig := make([]byte, ed25519.SignatureSize)

	if err := v.Verify(data, badSig); err == nil {
		t.Fatal("expected verification to fail with bad signature")
	}
}

func TestVaultClientBadAddr(t *testing.T) {
	_, err := vault.NewClient(vault.Config{
		Addr:  "http://127.0.0.1:1",
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("new client should succeed (connection happens at use): %v", err)
	}
}

func TestVaultClientEmptyAddr(t *testing.T) {
	_, err := vault.NewClient(vault.Config{})
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}
