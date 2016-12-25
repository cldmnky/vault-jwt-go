package vault_jwt_test

import (
	"net"
	"testing"
	"time"

	"github.com/cldmnky/vault-jwt-go"
	"github.com/dgrijalva/jwt-go"
	vaultapi "github.com/hashicorp/vault/api"
	logicaltransit "github.com/hashicorp/vault/builtin/logical/transit"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
)

type MyCustomClaims struct {
	Foo string `json:"foo"`
	jwt.StandardClaims
}

func TestVault(t *testing.T) {
	ln, vaultClient, vaultConfig, vaultToken := initVault(t)
	defer ln.Close()

	claims, config := getConf(vaultConfig, vaultToken)

	signed := testVaultSign(t, vaultClient, claims, config)
	testVaultVerify(t, vaultClient, config, signed)
}

func testVaultSign(t *testing.T, client *vaultapi.Client, claims MyCustomClaims, config vault_jwt.Config) string {
	_, err := client.Logical().Write("transit/keys/foo", map[string]interface{}{
		"type": "aes256-gcm96",
	})
	if err != nil {
		t.Fatal(err)
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("Vault"), claims)
	ss, _ := token.SignedString(config)
	return ss
}

func testVaultVerify(t *testing.T, client *vaultapi.Client, config vault_jwt.Config, sign string) {
	token, err := jwt.ParseWithClaims(sign, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return config, nil
	})

	if err != nil {
		t.Fatal(err)
	}

	claims, ok := token.Claims.(*MyCustomClaims)

	if ok && token.Valid {
		t.Logf("%v %v\n", claims.Foo, claims.StandardClaims.ExpiresAt)
	} else {
		t.Errorf("Token error %v\n", err)
	}
}

func initVault(t *testing.T) (net.Listener, *vaultapi.Client, *vaultapi.Config, string) {
	err := vault.AddTestLogicalBackend("transit", logicaltransit.Factory)
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := http.TestServer(t, core)

	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = addr

	vaultClient, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	vaultClient.SetToken(token)

	err = vaultClient.Sys().Mount("transit", &vaultapi.MountInput{
		Type: "transit",
	})
	if err != nil {
		panic(err)
	}

	_, err = vaultClient.Logical().Write("transit/keys/foo", map[string]interface{}{
		"type": "aes256-gcm96",
	})
	if err != nil {
		panic(err)
	}
	return ln, vaultClient, vaultConfig, token
}

func getConf(vaultConfig *vaultapi.Config, vaultToken string) (MyCustomClaims, vault_jwt.Config) {
	claims := MyCustomClaims{
		"bar",
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15000).Unix(),
			Issuer:    "test",
		},
	}

	config := vault_jwt.Config{
		vaultConfig,
		"foo",
		vaultToken,
		false,
	}
	return claims, config
}
