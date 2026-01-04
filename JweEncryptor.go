package oauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/rizvn/panics"
)

type JweEncryptor struct {
	PublicKeyPath  string
	PrivateKeyPath string
	encPublicKey   *rsa.PublicKey
	encPrivateKey  *rsa.PrivateKey
}

func (r *JweEncryptor) Init() {
	pubkey, err := os.ReadFile(r.PublicKeyPath)
	panics.OnError(err, "failed to read public key file")

	privkey, err := os.ReadFile(r.PrivateKeyPath)
	panics.OnError(err, "failed to read private key file")

	// Parse RSA keys
	pemBlock, _ := pem.Decode(pubkey)
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	panics.OnError(err, "failed to parse OIDC encryption public key")
	r.encPublicKey = pubKey.(*rsa.PublicKey)

	// Parse private key
	pemBlock, _ = pem.Decode(privkey)
	privKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	panics.OnError(err, "failed to parse OIDC encryption private key")
	r.encPrivateKey = privKey.(*rsa.PrivateKey)
}

func (r *JweEncryptor) Encrypt(input string) string {
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: r.encPublicKey},
		nil,
	)

	panics.OnError(err, "failed to create JWE encrypter")

	object, err := encrypter.Encrypt([]byte(input))
	panics.OnError(err, "failed to encrypt access token")

	jweToken, err := object.CompactSerialize()
	panics.OnError(err, "failed to serialize JWE token")

	return jweToken
}

func (r *JweEncryptor) Decrypt(input string) string {
	object, err := jose.ParseEncrypted(input, []jose.KeyAlgorithm{jose.RSA_OAEP},
		[]jose.ContentEncryption{jose.A128GCM})

	panics.OnError(err, "failed to parse encrypted access token")

	decrypted, err := object.Decrypt(r.encPrivateKey)
	panics.OnError(err, "failed to decrypt access token")

	return string(decrypted)
}
