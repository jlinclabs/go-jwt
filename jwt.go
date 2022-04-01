package jwt

import (
	"crypto/ed25519"
)

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}
type EdDsaHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	JWS       Jws
}
type Jws struct {
	Kty string            `json:"kty"`
	Crv string            `json:"crv"`
	X   ed25519.PublicKey `json:"x"`
}

type Jwt struct {
	Head      Header
	Payload   map[string]interface{}
	Signature []byte
}
type EdDsaJwt struct {
	Head      EdDsaHeader
	Payload   map[string]interface{}
	Signature []byte
}
