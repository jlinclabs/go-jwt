package jwt

import (
	"testing"
)

const hmacSecret = "534564475bba596939661399b103ab7a2c6d4797eca789c91bd267b135a6b74c"
const goodJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.FybOQqZ9q17FZMvEKCFH2h7H4tRgSJV7vcxZX6tlZpw"

func TestSignHmac(t *testing.T) {
	signed, err := SignHmac(`{"foo":"bar"}`, hmacSecret)
	if err != nil {
		t.Errorf("Error should be nil: %s", err)
	}
	if signed != goodJwt {
		t.Errorf("Wanted %s, got %s", goodJwt, signed)
	}

	notSigned, err := SignHmac(`notJSON`, hmacSecret)
	if notSigned != "" {
		t.Errorf("Wanted empty string, got %s", notSigned)
	}
	badJSONmessage := "Payload must be valid JSON"
	if err.Error() != badJSONmessage {
		t.Errorf("Should fail on invalid JSON, wanted %s, got %s", badJSONmessage, err)
	}
}
