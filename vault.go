package vault_jwt

import (
	"github.com/dgrijalva/jwt-go"
)

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
