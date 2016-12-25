package vault_jwt

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/api"
	"log"
	"net/http"
)

type Config struct {
	VaultConfig *api.Config
	Path        string
	Token       string
	SSLEnabled  bool
}

func newVaultClient(config *Config) (*api.Client, error) {
	log.Printf("[INFO] (vault_jwt) creating vault/api client")
	vaultConfig := config.VaultConfig

	if config.SSLEnabled {
		tlsConfig := &tls.Config{}
		vaultConfig.HttpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	// return client
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}
	if config.Token != "" {
		log.Printf("[DEBUG] (vault_jwt) setting vault token")
		client.SetToken(config.Token)
	} else {
		log.Fatalln("[ERROR] (vault_jwt) no vault token")
	}
	return client, nil
}

// Implements the transit secret backend in Vault for signing.

type SigningMethodVault struct{}

func init() {
	jwt.RegisterSigningMethod("Vault", func() jwt.SigningMethod {
		return &SigningMethodVault{}
	})
}

func (s *SigningMethodVault) Alg() string {
	return "Vault" // Non-standard!
}

func (s *SigningMethodVault) Sign(signingString string, key interface{}) (string, error) {
	config, ok := key.(Config)
	if !ok {
		log.Fatal("Bad config")
	}

	client, err := newVaultClient(&config)
	if err != nil {
		log.Fatalf("Error when creating client: %s", err)
	}

	secret, err := client.Logical().Write("transit/hmac/"+config.Path, map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(signingString)),
	})

	returnString, ok := secret.Data["hmac"].(string)
	if !ok {
		log.Fatal("Bad return from vault")
	}

	return jwt.EncodeSegment([]byte(returnString)), nil
}

func (s *SigningMethodVault) Verify(signingString, signature string, key interface{}) error {
	var sig []byte
	var err error
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	config, ok := key.(Config)
	if !ok {
		log.Fatal("Bad config")
	}

	client, err := newVaultClient(&config)
	if err != nil {
		log.Fatalf("Error when creating client: %s", err)
	}

	result, err := client.Logical().Write("transit/verify/"+config.Path, map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(signingString)),
		"hmac":  string(sig),
	})
	if err != nil {
		log.Fatal("Error in request to vault")
	}

	isValid, ok := result.Data["valid"].(bool)
	if !ok {
		return errors.New("Bad response from vault")
	}
	if !isValid {
		return errors.New("INVALID")
	}
	return nil
}
