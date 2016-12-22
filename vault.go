package vault_jwt

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
)

type Config struct {
	VaultConfig *api.Config
	Path        string
	Token       string
	SSLEnabled  bool
}

func newVaultClient(config *Config) (*api.Client, error) {
	log.Printf("[INFO] (vault_jwt) creating vault/api client")
	// Create the default config object
	vaultConfig := api.DefaultConfig()

	// merge configs
	if err := mergo.Merge(&vaultConfig, config.VaultConfig); err != nil {
		log.Printf("[ERROR] (vault_jwt) could not merge configs", err)
		return nil, err
	}
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
	return "", nil
}

func (s *SigningMethodVault) Verify(signingString, signature string, key interface{}) error {
	return nil
}
