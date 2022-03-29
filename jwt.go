package jwt

import (
	"crypto/ed25519"
)

type Header struct {
	Algorithm string
	Type      string
	JWS       Jws
}
type Jws struct {
	Kty string
	Crv string
	X   ed25519.PublicKey
}

type Jwt struct {
	Head      Header
	Payload   map[string]interface{}
	Signature []byte
}
