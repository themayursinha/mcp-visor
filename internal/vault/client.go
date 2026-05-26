package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	addr      string
	token     string
	namespace string
	client    *http.Client
}

type Config struct {
	Addr       string
	Token      string
	Namespace  string
	CACert     string
	SkipVerify bool
	Timeout    time.Duration
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vault address required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault token required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	transport := &http.Transport{}
	if cfg.CACert != "" || cfg.SkipVerify {
		tc := &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		}
		if cfg.CACert != "" {
			caCert, err := os.ReadFile(cfg.CACert)
			if err != nil {
				return nil, fmt.Errorf("read CA cert: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tc.RootCAs = caCertPool
		}
		transport.TLSClientConfig = tc
	}

	return &Client{
		addr:      strings.TrimRight(cfg.Addr, "/"),
		token:     cfg.Token,
		namespace: cfg.Namespace,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}, nil
}

func (c *Client) Sign(ctx context.Context, keyName string, data []byte) (string, error) {
	input := base64.StdEncoding.EncodeToString(data)
	body := map[string]string{"input": input}
	payload, _ := json.Marshal(body)

	path := fmt.Sprintf("/v1/transit/sign/%s", keyName)
	resp, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return "", fmt.Errorf("vault sign: %w", err)
	}

	sig, ok := resp["signature"].(string)
	if !ok || sig == "" {
		return "", fmt.Errorf("vault sign: empty signature in response")
	}
	return sig, nil
}

func (c *Client) Verify(ctx context.Context, keyName string, data []byte, signature string) (bool, error) {
	input := base64.StdEncoding.EncodeToString(data)
	body := map[string]string{
		"input":     input,
		"signature": signature,
	}
	payload, _ := json.Marshal(body)

	path := fmt.Sprintf("/v1/transit/verify/%s", keyName)
	resp, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return false, fmt.Errorf("vault verify: %w", err)
	}

	valid, _ := resp["valid"].(bool)
	return valid, nil
}

func (c *Client) GetPublicKey(ctx context.Context, keyName string) (ed25519.PublicKey, error) {
	path := fmt.Sprintf("/v1/transit/keys/%s", keyName)
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("vault read key: %w", err)
	}

	keysRaw, ok := resp["keys"]
	if !ok {
		return nil, fmt.Errorf("vault read key: no keys in response")
	}
	keys, ok := keysRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault read key: unexpected keys format")
	}

	latestKey, ok := keys["1"]
	if !ok {
		for _, v := range keys {
			latestKey = v
			break
		}
	}
	if latestKey == nil {
		return nil, fmt.Errorf("vault read key: no key versions found")
	}

	keyMap, ok := latestKey.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault read key: unexpected key version format")
	}

	pubKeyStr, ok := keyMap["public_key"].(string)
	if !ok || pubKeyStr == "" {
		return nil, fmt.Errorf("vault read key: no public_key in key metadata")
	}

	pubKey, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("vault read key: decode public_key: %w", err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("vault read key: unexpected public key size %d", len(pubKey))
	}

	return ed25519.PublicKey(pubKey), nil
}

func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/sys/health", nil)
	if err != nil {
		return fmt.Errorf("vault health: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault unhealthy: %s (%s)", resp.Status, string(body))
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	c.setHeaders(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(respBody))
	}

	var envelope struct {
		Data   map[string]any `json:"data"`
		Errors []string        `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		return nil, fmt.Errorf("vault errors: %v", envelope.Errors)
	}
	if envelope.Data == nil {
		return map[string]any{}, nil
	}
	return envelope.Data, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Accept", "application/json")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
}

func (c *Client) Addr() string { return c.addr }

func parseVaultSignature(vaultSig string) ([]byte, error) {
	parts := strings.SplitN(vaultSig, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || parts[1] != "v1" {
		return nil, fmt.Errorf("unexpected vault signature format: %s", vaultSig)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode vault signature: %w", err)
	}
	return raw, nil
}
