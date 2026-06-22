package proxy

import (
	"fmt"

	"github.com/themayursinha/mcp-visor/internal/signer"
	"github.com/themayursinha/mcp-visor/internal/vault"
)

func (cfg Config) buildSigner() (signer.Signer, error) {
	if cfg.Vault.Addr == "" {
		return nil, nil
	}

	vc := vault.Config{
		Addr:       cfg.Vault.Addr,
		Token:      cfg.Vault.Token,
		Namespace:  cfg.Vault.Namespace,
		CACert:     cfg.Vault.CACert,
		SkipVerify: cfg.Vault.SkipVerify,
	}
	client, err := vault.NewClient(vc)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}

	keyName := cfg.Vault.KeyName
	if keyName == "" {
		keyName = "mcp-visor-approval"
	}

	s, err := vault.NewTransitSigner(client, keyName)
	if err != nil {
		return nil, fmt.Errorf("vault transit signer: %w", err)
	}
	return s, nil
}
