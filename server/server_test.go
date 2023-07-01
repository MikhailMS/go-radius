package server

import (
  "testing"

  "github.com/stretchr/testify/assert"

  "github.com/MikhailMS/go-radius/protocol"
)

func TestCreateReplyPacket(t *testing.T) {
  expectedReplyBytes := []uint8 { 5, 43, 0, 29, 109, 214, 15, 125, 92, 239, 190, 144, 171, 115, 202, 187, 72, 208, 115, 25, 1, 9, 116, 101, 115, 116, 105, 110, 103 }

  dictPath      := "../dict_examples/integration_dict"
  dictionary, _ := protocol.DictionaryFromFile(dictPath)
  allowedHosts  := make(map[string]string)

  allowedHosts["123.123.123.123"] = "secret"
  
  server := InitialiseServer(dictionary, allowedHosts, "127.0.0.1", 1, 2)

  userName        := []uint8("testing")
  userNameAttr, _ := server.CreateAttributeByName("User-Name", &userName)
  attributes      := []protocol.RadiusAttribute { userNameAttr }

  request := []uint8 { 4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100 }

  replyPacket, _      := server.CreateReplyPacket(protocol.AccountingResponse, attributes, &request, server.Secret("123.123.123.123"))
  replyPacketBytes, _ := replyPacket.ToBytes()
  assert.Equal(t, expectedReplyBytes, replyPacketBytes, "Reply bytes do not match!")
}
