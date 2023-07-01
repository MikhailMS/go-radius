package client

import (
  "fmt"
  "testing"

  "github.com/stretchr/testify/assert"

  "github.com/MikhailMS/go-radius/tools"
  "github.com/MikhailMS/go-radius/protocol"
)

func TestGetRadiusAttributeOriginalStringValue(t *testing.T) {
  fmt.Println("TESTS")
  
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  userName        := []uint8("testing")
  userNameAttr, _ := client.CreateAttributeByName("User-Name", &userName)

  origString, _ := client.RadiusAttrOriginalStringValue(userNameAttr)
  assert.Equal(t, string(userName), origString, "Original value is not restored!")
}

func TestGetRadiusAttributeOriginalStringValueError(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  userName        := []uint8 { 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73 }
  userNameAttr, _ := client.CreateAttributeByName("User-Name", &userName)

  _, err := client.RadiusAttrOriginalStringValue(userNameAttr)
  assert.Equal(t, "Error while decoding original value of attribute with ID: 1", err.Error(), "Original value is restored!")
}

func TestGetRadiusAttributeOriginalIntegerValue(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  value      := uint32(10)
  valueBytes := tools.IntegerToBytes(value)
  nasPortAttr, _ := client.CreateAttributeByName("NAS-Port-Id", &valueBytes)

  origInteger, _ := client.RadiusAttrOriginalIntegerValue(nasPortAttr)
  assert.Equal(t, value, origInteger, "Original value is not restored!")
}

func TestGetRadiusAttributeOriginalIntegerValueError(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  invalidValue   := []uint8 { 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73 }
  nasPortAttr, _ := client.CreateAttributeByName("NAS-Port-Id", &invalidValue)

  _, err := client.RadiusAttrOriginalIntegerValue(nasPortAttr)
  assert.Equal(t, "Error while decoding original value of attribute with ID: 5", err.Error(), "Original value is restored!")
}

func TestVerifyEmptyReply(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  callingSID        := []uint8("00-01-24-80-B3-9C")
  callingSIDAttr, _ := client.CreateAttributeByName("Calling-Station-Id", &callingSID)
  attributes        := []protocol.RadiusAttribute { callingSIDAttr }

  authenticator := []uint8 { 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73 }
  reply         := []uint8 {}
  
  radPacket := client.CreateRadiusPacket(protocol.AccountingRequest)

  radPacket.SetAttributes(attributes)
  radPacket.OverrideID(43)
  radPacket.OverrideAuthenticator(authenticator)

  _, err := client.VerifyReply(&radPacket, &reply)
  assert.Equal(t, "Empty reply", err.Error(), "Invalid reply is verified!")
}

func TestVerifyMalformedReply(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  callingSID        := []uint8("00-01-24-80-B3-9C")
  callingSIDAttr, _ := client.CreateAttributeByName("Calling-Station-Id", &callingSID)
  attributes        := []protocol.RadiusAttribute { callingSIDAttr }

  authenticator := []uint8 { 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73 }
  reply         := []uint8 { 43, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73 }
  
  radPacket := client.CreateRadiusPacket(protocol.AccountingRequest)

  radPacket.SetAttributes(attributes)
  radPacket.OverrideID(43)
  radPacket.OverrideAuthenticator(authenticator)

  _, err := client.VerifyReply(&radPacket, &reply)
  assert.Equal(t, "Packet identifier mismatch", err.Error(), "Invalid reply is verified!")
}

func TestVerifyReply(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  
  client := InitialiseClient(dictionary, "127.0.0.1", "secret", 1, 2)

  userName        := []uint8("testing")
  userNameAttr, _ := client.CreateAttributeByName("User-Name", &userName)
  attributes      := []protocol.RadiusAttribute { userNameAttr }

  authenticator := []uint8 { 152, 137, 115, 14, 56, 250, 103, 56, 57, 57, 104, 246, 226, 80, 71, 167 }
  reply         := []uint8 { 2, 220, 0, 52, 165, 196, 239, 87, 197, 230, 219, 74, 148, 177, 209, 155, 35, 36, 236, 63, 6, 6, 0, 0, 0, 2, 8, 6, 192, 168, 0, 1, 97, 20, 0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }
  
  radPacket := client.CreateRadiusPacket(protocol.AccessRequest)

  radPacket.SetAttributes(attributes)
  radPacket.OverrideID(220)
  radPacket.OverrideAuthenticator(authenticator)

  ok, _ := client.VerifyReply(&radPacket, &reply)
  assert.Equal(t, true, ok, "Valid reply is not verified!")
}
