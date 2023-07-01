package protocol

import (
  "testing"

  "github.com/stretchr/testify/assert"

  "github.com/MikhailMS/go-radius/tools"
)

func TestCreateRadAttributeByName(t *testing.T) {
  expectedRadAttr := RadiusAttribute { 1, "User-Name", []uint8 { 1,2,3 } }

  dictPath      := "../dict_examples/test_dictionary_dict"
  dictionary, _ := DictionaryFromFile(dictPath)

  radiusAttribute, _ := CreateRadAttributeByName(&dictionary, "User-Name", &[]uint8 { 1,2,3 })
  assert.Equal(t, expectedRadAttr, radiusAttribute, "Radius Attributes are not same!")
}

func TestCreateRadAttributeByNameNonExisting(t *testing.T) {
  expectedRadAttr := RadiusAttribute{}

  dictPath      := "../dict_examples/test_dictionary_dict"
  dictionary, _ := DictionaryFromFile(dictPath)

  radiusAttribute, ok := CreateRadAttributeByName(&dictionary, "Non-Existing", &[]uint8 { 1,2,3 })
  assert.Equal(t, expectedRadAttr, radiusAttribute, "Radius Attributes are not same!")
  assert.Equal(t, false, ok, "Radius Attributes are not same!")
}

func TestCreateRadAttributeByID(t *testing.T) {
  expectedRadAttr := RadiusAttribute { 5, "NAS-Port-Id", []uint8 { 1,2,3 } }

  dictPath      := "../dict_examples/test_dictionary_dict"
  dictionary, _ := DictionaryFromFile(dictPath)

  radiusAttribute, _ := CreateRadAttributeByID(&dictionary, 5, &[]uint8 { 1,2,3 })
  assert.Equal(t, expectedRadAttr, radiusAttribute, "Radius Attributes are not same!")
  
}

func TestCreateRadAttributeByIDNonExisting(t *testing.T) {
  expectedRadAttr := RadiusAttribute{}

  dictPath      := "../dict_examples/test_dictionary_dict"
  dictionary, _ := DictionaryFromFile(dictPath)

  radiusAttribute, ok := CreateRadAttributeByID(&dictionary, 205, &[]uint8 { 1,2,3 })
  assert.Equal(t, expectedRadAttr, radiusAttribute, "Radius Attributes are not same!")
  assert.Equal(t, false, ok, "Radius Attributes are not same!")
}

func TestInitialiseRadPacketFromBytes(t *testing.T) {
  radPacketBytes := []uint8 { 4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }

  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := DictionaryFromFile(dictPath)

  nasIPAddrBytes, _    := tools.IPv4StringToBytes("192.168.1.10")
  nasPortIDBytes       := tools.IntegerToBytes(0)
  nasID                := []uint8("trillian")
  calledSID            := []uint8("00-04-5F-00-0F-D1")
  callingSID           := []uint8("00-01-24-80-B3-9C")
  framedIPAddrBytes, _ := tools.IPv4StringToBytes("10.0.0.100")

  nasIPAttr,      _ := CreateRadAttributeByName(&dictionary, "NAS-IP-Address",     &nasIPAddrBytes)
  nasPortAttr,    _ := CreateRadAttributeByName(&dictionary, "NAS-Port-Id",        &nasPortIDBytes)
  nasIDAttr,      _ := CreateRadAttributeByName(&dictionary, "NAS-Identifier",     &nasID)
  calledSIDAttr,  _ := CreateRadAttributeByName(&dictionary, "Called-Station-Id",  &calledSID)
  callingSIDAttr, _ := CreateRadAttributeByName(&dictionary, "Calling-Station-Id", &callingSID)
  framedIPAttr,   _ := CreateRadAttributeByName(&dictionary, "Framed-IP-Address",  &framedIPAddrBytes)

  attributes := []RadiusAttribute { nasIPAttr, nasPortAttr, nasIDAttr, calledSIDAttr, callingSIDAttr, framedIPAttr }
  authenticator := []uint8 { 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73 }

  expectedPacket := InitialiseRadiusPacket(AccountingRequest)

  expectedPacket.SetAttributes(attributes)
  expectedPacket.OverrideID(43)
  expectedPacket.OverrideAuthenticator(authenticator)

  packetFromBytes, _ := InitialiseRadiusPacketFromBytes(&dictionary, &radPacketBytes)
  assert.Equal(t, expectedPacket, packetFromBytes, "Radius Packets are not same!")
}

func TestOverrideID(t *testing.T) {
  expectedID := uint8(50)

  radPacket := InitialiseRadiusPacket(AccountingRequest)

  radPacket.OverrideID(expectedID)
  assert.Equal(t, expectedID, radPacket.ID(), "Radius Packet ID was not changed!")
}

func TestOverrideAuthenticator(t *testing.T) {
  expectedAuthenticator := []uint8 { 0, 25, 100, 56, 13 }

  radPacket := InitialiseRadiusPacket(AccountingRequest)

  radPacket.OverrideAuthenticator(expectedAuthenticator)
  assert.Equal(t, expectedAuthenticator, radPacket.Authenticator(), "Radius Packet Authhenticator was not changed!")
}

func TestRadiusPacketToBytes(t *testing.T) {
  expectedPacketBytes := []uint8 { 1, 50, 0, 29, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3, 1, 9, 116, 101, 115, 116, 105, 110, 103 }
  
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := DictionaryFromFile(dictPath)

  userName        := []uint8("testing")
  userNameAttr, _ := CreateRadAttributeByName(&dictionary, "User-Name", &userName)
  attributes      := []RadiusAttribute { userNameAttr }
  newAuthenticator := []uint8 { 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3 }

  radPacket := InitialiseRadiusPacket(AccessRequest)
  radPacket.SetAttributes(attributes)
  radPacket.OverrideID(50)
  radPacket.OverrideAuthenticator(newAuthenticator)

  packetBytes, _ := radPacket.ToBytes()
  assert.Equal(t, expectedPacketBytes, packetBytes, "Radius Packet was not converted to correct bytes!")
}

func TestOverrideMessageAuthenticator(t *testing.T) {
  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := DictionaryFromFile(dictPath)
  
  initMessageAuthenticator := []uint8 { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  newMessageAuthenticator  := []uint8 { 1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153 }
  msgAuthAttr, _           := CreateRadAttributeByName(&dictionary, "Message-Authenticator", &initMessageAuthenticator)
  attributes               := []RadiusAttribute { msgAuthAttr }

  radPacket := InitialiseRadiusPacket(AccessRequest)
  radPacket.SetAttributes(attributes)

  radPacket.OverrideMessageAuthenticator(newMessageAuthenticator)

  msgAuthenticator, _ := radPacket.MessageAuthenticator()
  assert.Equal(t, newMessageAuthenticator, msgAuthenticator, "Radius Packet Authhenticator was not changed!") 
}

func TestGenerateMessageAuthenticator(t *testing.T) {
  expectedMessageAuthenticatorBytes := []uint8 { 85, 134, 2, 170, 83, 101, 202, 79, 109, 163, 59, 12, 66, 170, 183, 220 }

  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := DictionaryFromFile(dictPath)
  
  secret           := "secret"
  newAuthenticator := []uint8 { 152, 137, 115, 14, 56, 250, 103, 56, 57, 57, 104, 246, 226, 80, 71, 167 }

  userName         := []uint8("testing")
  messageAuthBytes := make([]uint8, 16)

  userNameAttr, _ := CreateRadAttributeByName(&dictionary, "User-Name",             &userName)
  msgAuthAttr, _  := CreateRadAttributeByName(&dictionary, "Message-Authenticator", &messageAuthBytes)
  attributes      := []RadiusAttribute { userNameAttr, msgAuthAttr }

  radPacket := InitialiseRadiusPacket(AccessRequest)
  radPacket.SetAttributes(attributes)
  radPacket.OverrideID(220)
  radPacket.OverrideAuthenticator(newAuthenticator)

  radPacket.GenerateMessageAuthenticator(secret)

  msgAuthenticator, _ := radPacket.MessageAuthenticator()
  assert.Equal(t, expectedMessageAuthenticatorBytes, msgAuthenticator, "Radius Packet Message Authhenticator was not set to correct bytes!")
}
