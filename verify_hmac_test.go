package jwt

import (
	"testing"
)

const hmacSecret1 = "6421187a386761e1c95e8a550777b341fea0de00bd73db21c58a784c777c41e7"
const payload1 = `{"onething":"this","theotherthing":"that"}`
const goodJwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvbmV0aGluZyI6InRoaXMiLCJ0aGVvdGhlcnRoaW5nIjoidGhhdCJ9.AHJvSUY5ehSP8LWeeESbjMxemAxksVSVQxksyX5fnlE"
const badSigJwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvbmV0aGluZyI6InRoaXMiLCJ0aGVvdGhlcnRoaW5nIjoidGhhdCJ9.AHJwSUY5ehSP8LWeeESbjMxemAxksVSVQxksyX5fnlE"
const badHeader1 = "eyJhbGciOiJOT1QyNTYiLCJ0eXAiOiJKV1QifQ.eyJvbmV0aGluZyI6InRoaXMiLCJ0aGVvdGhlcnRoaW5nIjoidGhhdCJ9.AHJvSUY5ehSP8LWeeESbjMxemAxksVSVQxksyX5fnlE"

func TestVerifyHmac(t *testing.T) {
	payloadJson, err := VerifyHmac(goodJwt1, []byte(hmacSecret1))
	if err != nil {
		t.Errorf("Error should be nil: %s", err)
	}
	if payloadJson != payload1 {
		t.Errorf("Wanted %s, got %s", payload1, payloadJson)
	}

	payloadJson, err = VerifyHmac(badSigJwt1, []byte(hmacSecret1))
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badJSONmessage1 := "Signature not verified"
	if err.Error() != badJSONmessage1 {
		t.Errorf("Should fail on bad signature, wanted %s, got %s", badJSONmessage1, err)
	}

	payloadJson, err = VerifyHmac(badHeader1, []byte(hmacSecret1))
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badHeaderMessage1 := "HS256 algorithm not specified in header"
	if err.Error() != badHeaderMessage1 {
		t.Errorf("Should fail on bad header, wanted %s, got %s", badHeaderMessage1, err)
	}

	payloadJson, err = VerifyHmac("eyJhbGciOiJOT1QyNTYiLCJ0eXAiOiJKV1QifQ.eyJvbmV0aGluZyI6InRoaXMiLCJ0aGVvdGhlcnRoaW5nIjoidGhhdCJ9", []byte(hmacSecret1))
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badJwtMessage1 := "Not a valid JWT format"
	if err.Error() != badJwtMessage1 {
		t.Errorf("Should fail on malformed JWT, wanted %s, got %s", badJwtMessage1, err)
	}

}
