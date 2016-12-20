package vault_jwt

"github.com/dgrijalva/jwt-go"

// Implements the transit secret backend in Vault for signing.

type SigningMethodVault struct{}



func init() {
    jwt.RegisterSigningMethod("Vault", func() jwt.SigningMethod {
        return &SigningMethodVault{}
    })
}


func (s *SigningMethodVault) Sign(signingString string, key interface{}) (string, error) {

}

func (s *SigningMethodVault) Verify(signingString, signature string, key interface{}) error {

}
