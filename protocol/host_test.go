package protocol

import (
  "testing"

  "github.com/stretchr/testify/assert"
)

func TestGetDictionaryValueByAttrAndValueName(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)

  host := InitialiseHost(1812, 1813, 3799, dictionary)

  dictValue, _ := host.DictionaryValueByAttrAndValueName("Service-Type", "Login-User")

  assert.Equal(t, "Service-Type", dictValue.AttributeName(), "Dictionary attribute names are not same!")
  assert.Equal(t, "Login-User",   dictValue.Name(),          "Dictionary names are not same!")
  assert.Equal(t, "1",            dictValue.Value(),         "Dictionary values are not same!")
}

func TestGetDictionaryValueByAttrAndValueNameError(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)

  host := InitialiseHost(1812, 1813, 3799, dictionary)

  _, ok := host.DictionaryValueByAttrAndValueName("Service-Type", "Lin-User")

  assert.Equal(t, false, ok, "Dictionary value was found (expected to not exist)!")
}

func TestGetDictionaryAttributeByID(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)

  host := InitialiseHost(1812, 1813, 3799, dictionary)

  dictAttr, _ := host.DictionaryAttributeByID(80)

  assert.Equal(t, "Message-Authenticator", dictAttr.Name(),     "Dictionary attribute names are not same!")
  assert.Equal(t, uint8(80),               dictAttr.Code(),     "Dictionary names are not same!")
  assert.Equal(t, ByteString,              dictAttr.CodeType(), "Dictionary values are not same!")
}

func TestGetDictionaryAttributeByIDError(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)

  host := InitialiseHost(1812, 1813, 3799, dictionary)

  _, ok := host.DictionaryAttributeByID(255)

  assert.Equal(t, false, ok, "Dictionary attribute was found (expected to not exist)!")
}

func TestVerifyPacketAttributes(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)

  packetBytes := []uint8 { 4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }
  
  host        := InitialiseHost(1812, 1813, 3799, dictionary)

  err := host.VerifyPacketAttributes(&packetBytes)
  assert.Equal(t, nil, err, "Valid packet is not verified!")
}

func TestVerifyPacketAttributesFail(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)

  packetBytes := []uint8 { 4, 43, 0, 82, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 5, 192, 168, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }
  host        := InitialiseHost(1812, 1813, 3799, dictionary)

  err := host.VerifyPacketAttributes(&packetBytes)
  assert.Equal(t, "Cannot verify original value of attribute with ID 4", err.Error(), "Invalid packed is verified!")
}

func TestVerifyMessageAuthenticator(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)
  secret     := "secret"

  packetBytes := []uint8 { 1, 120, 0, 185, 49, 79, 108, 150, 27, 203, 166, 51, 193, 68, 15, 76, 208, 114, 171, 48, 1, 9, 116, 101, 115, 116, 105, 110, 103, 80, 18, 164, 201, 132, 0, 209, 101, 200, 189, 252, 251, 120, 224, 74, 190, 232, 197, 2, 66, 85, 125, 163, 190, 40, 210, 235, 231, 112, 96, 7, 94, 27, 95, 241, 63, 23, 81, 25, 136, 36, 209, 238, 119, 131, 113, 118, 14, 160, 16, 94, 184, 143, 37, 193, 138, 124, 238, 85, 197, 21, 17, 206, 158, 87, 132, 239, 59, 82, 183, 175, 54, 124, 138, 5, 245, 166, 195, 181, 106, 41, 31, 129, 183, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 6, 6, 0, 0, 0, 2, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }
  host        := InitialiseHost(1812, 1813, 3799, dictionary)

  err := host.VerifyMessageAuthenticator(secret, &packetBytes)
  assert.Equal(t, nil, err, "Invalid packed is verified!")
}

func TestVerifyMessageAuthenticatorWoAuthenticator(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)
  secret     := "secret"

  packetBytes := []uint8 { 4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }
  host        := InitialiseHost(1812, 1813, 3799, dictionary)

  err := host.VerifyMessageAuthenticator(secret, &packetBytes)
  assert.Equal(t, "Packet Message-Authenticator mismatch", err.Error(), "Invalid packed is verified!")
}

func TestVerifyMessageAuthenticatorError(t *testing.T) {
  dictPath   := "../dict_examples/integration_dict"
  dictionary := DictionaryFromFile(dictPath)
  secret     := "secret"

  packetBytes := []uint8 { 1, 94, 0, 190, 241, 228, 181, 142, 185, 194, 157, 205, 159, 0, 91, 199, 171, 119, 68, 44, 1, 9, 116, 101, 115, 116, 105, 110, 103, 80, 23, 109, 101, 115, 115, 97, 103, 101, 45, 97, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 2, 66, 167, 81, 185, 84, 173, 104, 91, 10, 145, 109, 156, 169, 227, 109, 100, 76, 86, 227, 61, 253, 129, 35, 109, 115, 54, 140, 66, 106, 193, 70, 145, 39, 106, 105, 142, 215, 21, 166, 142, 80, 145, 217, 202, 252, 172, 33, 17, 12, 159, 105, 157, 144, 221, 221, 94, 48, 158, 22, 62, 191, 16, 177, 137, 131, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 6, 6, 0, 0, 0, 2, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }
  host        := InitialiseHost(1812, 1813, 3799, dictionary)

  err := host.VerifyMessageAuthenticator(secret, &packetBytes)
  assert.Equal(t, "Packet Message-Authenticator mismatch", err.Error(), "Invalid packed is verified!")
}
