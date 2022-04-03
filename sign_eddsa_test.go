package jwt

import (
	"testing"
)

const testPublicKey1 = "tfEkE0CQx4YCEQV-RLa8ImdSCiLZkyexNgSYxvMEr5s"
const testPrivateKey1 = "7reNdm-RZHiZjH_sZcrwtfF1x8tIhTPbGBPASzAS29a18SQTQJDHhgIRBX5EtrwiZ1IKItmTJ7E2BJjG8wSvmw"
const didKeyUrl1 = "did:jlinc:tfEkE0CQx4YCEQV-RLa8ImdSCiLZkyexNgSYxvMEr5s"
const goodJwt2 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InRmRWtFMENReDRZQ0VRVi1STGE4SW1kU0NpTFpreWV4TmdTWXh2TUVyNXMiLCJraWQiOiJkaWQ6amxpbmM6dGZFa0UwQ1F4NFlDRVFWLVJMYThJbWRTQ2lMWmt5ZXhOZ1NZeHZNRXI1cyJ9fQ.eyJhIjoiYWxwaGEiLCJiIjoiYmV0YSJ9.cnOe2srOcAZIvadZtkqvoJouAc5HgpAef-BcfR6d4sOc6kH0mTvTWeML7n2bnduK9j7eoWgpr8mr1PjPr9IxDg"

func TestSignEdDsa(t *testing.T) {
	signed, err := SignEdDsa(`{"a":"alpha","b":"beta"}`, testPublicKey1, testPrivateKey1, didKeyUrl1)
	if err != nil {
		t.Errorf("Error should be nil: %s", err)
	}
	if signed != goodJwt2 {
		t.Errorf("Wanted %s, got %s", goodJwt2, signed)
	}

	notSigned, err := SignEdDsa(`notJSON`, testPublicKey1, testPrivateKey1, didKeyUrl1)
	if notSigned != "" {
		t.Errorf("Wanted empty string, got %s", notSigned)
	}
	badJSONmessage := "Payload must be valid JSON"
	if err.Error() != badJSONmessage {
		t.Errorf("Should fail on invalid JSON, wanted %s, got %s", badJSONmessage, err)
	}
}
