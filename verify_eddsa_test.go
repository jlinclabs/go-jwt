package jwt

import (
	"testing"
)

const testPublicKey3 = "rBp0kYf57tQY0xCOvqsqtSwbgHZIbD2vdsst_bkSxY8"
const testPrivateKey3 = "YVWP4O7Wz_gpV0aIQ-jvw4Emu5XzJ-e7PKJpl9XuRGusGnSRh_nu1BjTEI6-qyq1LBuAdkhsPa92yy39uRLFjw"
const didKeyUrl3 = "did:jlinc:rBp0kYf57tQY0xCOvqsqtSwbgHZIbD2vdsst_bkSxY8"
const payload3 = `{"g":"gamma","d":"delta"}`
const goodJwt3 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJCcDBrWWY1N3RRWTB4Q092cXNxdFN3YmdIWkliRDJ2ZHNzdF9ia1N4WTgiLCJraWQiOiJkaWQ6amxpbmM6ckJwMGtZZjU3dFFZMHhDT3Zxc3F0U3diZ0haSWJEMnZkc3N0X2JrU3hZOCJ9fQ.eyJnIjoiZ2FtbWEiLCJkIjoiZGVsdGEifQ.zuW1tzofKYyoBthToZ4dRz_ZqjzgrUntJL_MMSDuhHcFswffBPFs9hs9nbold2J77g2XR48wMbyJUFZTa2c1AQ"
const badSigJwt3 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJCcDBrWWY1N3RRWTB4Q092cXNxdFN3YmdIWkliRDJ2ZHNzdF9ia1N4WTgiLCJraWQiOiJkaWQ6amxpbmM6ckJwMGtZZjU3dFFZMHhDT3Zxc3F0U3diZ0haSWJEMnZkc3N0X2JrU3hZOCJ9fQ.eyJnIjoiZ2FtbWEiLCJkIjoiZGVsdGEifQ.zuW1tzofKYyzBthToZ4dRz_ZqjzgrUntJL_MMSDuhHcFswffBPFs9hs9nbold2J77g2XR48wMbyJUFZTa2c1AQ"
const badHeader3 = "eyJhbGciOiJub3REU0EiLCJ0eXAiOiJKV1QiLCJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJyQnAwa1lmNTd0UVkweENPdnFzcXRTd2JnSFpJYkQydmRzc3RfYmtTeFk4Iiwia2lkIjoiZGlkOmpsaW5jOnJCcDBrWWY1N3RRWTB4Q092cXNxdFN3YmdIWkliRDJ2ZHNzdF9ia1N4WTgifX0.eyJnIjoiZ2FtbWEiLCJkIjoiZGVsdGEifQ.zuW1tzofKYyoBthToZ4dRz_ZqjzgrUntJL_MMSDuhHcFswffBPFs9hs9nbold2J77g2XR48wMbyJUFZTa2c1AQ"
const badJwt3 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJCcDBrWWY1N3RRWTB4Q092cXNxdFN3YmdIWkliRDJ2ZHNzdF9ia1N4WTgiLCJraWQiOiJkaWQ6amxpbmM6ckJwMGtZZjU3dFFZMHhDT3Zxc3F0U3diZ0haSWJEMnZkc3N0X2JrU3hZOCJ9fQ.eyJnIjoiZ2FtbWEiLCJkIjoiZGVsdGEifQ"

func TestVerifyEdDsa(t *testing.T) {
	payloadJson, err := VerifyEdDsa(goodJwt3, nil)
	if err != nil {
		t.Errorf("Error should be nil: %s", err)
	}
	if payloadJson != payload3 {
		t.Errorf("Wanted %s, got %s", payload3, payloadJson)
	}

	payloadJson, err = VerifyEdDsa(badSigJwt3, nil)
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badJSONmessage := "Signature not verified"
	if err.Error() != badJSONmessage {
		t.Errorf("Should fail on bad signature, wanted %s, got %s", badJSONmessage, err)
	}

	payloadJson, err = VerifyEdDsa(badHeader3, nil)
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badHeaderMessage := "EdDSA algorithm not specified in header"
	if err.Error() != badHeaderMessage {
		t.Errorf("Should fail on bad header, wanted %s, got %s", badHeaderMessage, err)
	}

	payloadJson, err = VerifyEdDsa(badJwt3, nil)
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badJwtMessage1 := "Not a valid JWT format"
	if err.Error() != badJwtMessage1 {
		t.Errorf("Should fail on malformed JWT, wanted %s, got %s", badJwtMessage1, err)
	}

	payloadJson, err = VerifyEdDsa(goodJwt3, []byte("badPublicKey"))
	if payloadJson != "" {
		t.Errorf("payloadJson should be empty: %s", payloadJson)
	}
	badJwtMessage2 := "No valid public key found"
	if err.Error() != badJwtMessage2 {
		t.Errorf("Should fail on bad public key, wanted %s, got %s", badJwtMessage2, err)
	}

}
