// RADIUS Packet implementation
package protocol

import (
  "math/rand"
)

// RadiusMsgType represents allowed types of RADIUS messages/packets
//
// Mainly used in RADIUS Server implementation to distinguish between sockets and functions, that should
// process RADIUS packets
type RadiusMsgType int

const (
  // Authentication packet
  AUTH RadiusMsgType = iota
  // Accounting packet
  ACCT
  // Change of Authorisation packet
  COA
)

// TypeCode represents all supported Codes of RADIUS message/packet
// as defined in RFC 2865 & RFC 3576
type TypeCode int

const (
  // AccessRequest      = 1
  AccessRequest TypeCode = iota
  // AccessAccept       = 2
  AccessAccept
  // AccessReject       = 3
  AccessReject
  // AccountingRequest  = 4
  AccountingRequest
  // AccountingResponse = 5
  AccountingResponse
  // AccessChallenge    = 11
  AccessChallenge
  // StatusServer       = 12
  StatusServer
  // StatusClient       = 13
  StatusClient
  // DisconnectRequest  = 40
  DisconnectRequest
  // DisconnectACK      = 41
  DisconnectACK
  // DisconnectNAK      = 42
  DisconnectNAK
  // CoARequest         = 43
  CoARequest
  // CoAACK             = 44
  CoAACK
  // CoANAK             = 45
  CoANAK
)

// RadiusAttribute represents an attribute, which would be sent to RADIUS Server/client as a part of RadiusPacket
type RadiusAttribute struct {
  id    uint8
  name  string
  value []uint8
}

// CreateByName creates RadiusAttribute with given name
//
// Returns nil if ATTRIBUTE with such name is not found in Dictionary
func CreateByName(dictionary *Dictionary, attributeName string, value *[]uint8) RadiusAttribute {
  for attr := range dictionary.Attributes() {
    if attr.Name() == attributeName {
      return RadiusAttribute {attr.Id, attributeName, value}
    }
  }

  return nil
}

// CreateByID creates RadiusAttribute with given id
//
// Returns nil if ATTRIBUTE with such id is not found in Dictionary
func CreateByID(dictionary *Dictionary, attributeID string, value *[]uint8) RadiusAttribute {
  for attr := range dictionary.Attributes() {
    if attr.Code() == attributeID {
      return RadiusAttribute {attributeID, attr.Name(), value}
    }
  }

  return nil
}

// OverrideValue overriddes RadiusAttribute value
//
// Mainly used when building Message-Authenticator
func (radAttr *RadiusAttribute) OverrideValue(newValue []uint8) {
  radAttr.value = newValue
}

// ID returns RadiusAttribute id
func (radAttr *RadiusAttribute) ID() uint8 {
  return radAttr.id
}

// Value returns RadiusAttribute value
func (radAttr *RadiusAttribute) Value() []uint8 {
  return radAttr.value
}

// Name returns RadiusAttribute name
func (radAttr *RadiusAttribute) Name() string {
  return radAttr.name
}

// VerifyOriginalValue verifies RadiusAttribute value, based on the ATTRIBUTE code type
func (radAttr *RadiusAttribute) VerifyOriginalValue(allowedType SupportedAttributeTypes) bool {
  switch allowedType {
    case AsciiString:
      if string(radAttr.value) {
        return true
      }
      return false
    case ByteString:
      if string(radAttr.value) {
        return true
      }
      return false
    case Concat:
      if string(radAttr.value) {
        return true
      }
      return false
    case Integer:
      if BytesToInteger(radAttr.value) {
        return true
      }
      return false
    case Integer64:
      // TODO: implement Integer64 convertion
      return false
    case Date:
      if BytesToTimestamp(radAttr.value) {
        return true
      }
      return false
    case IPv4Addr:
      if BytesToIPv4String(radAttr.value) {
        return true
      }
      return false
    case IPv4Prefix:
      // TODO: implement IPv4Prefix convertion
      return false
    case IPv6Addr:
      if BytesToIPv6String(radAttr.value) {
        return true
      }
      return false
    case IPv6Prefix:
      if BytesToIPv6String(radAttr.value) {
        return true
      }
      return false
    case InterfaceId:
      // TODO: implement InterfaceID convertion
      return false
    default:
      return false
  }
}

// OriginalStringValue returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type string, ipaddr,
// ipv6addr or ipv6prefix
func (radAttr *RadiusAttribute) OriginalStringValue(allowedType SupportedAttributeTypes) string {
  switch allowedType {
    case AsciiString:
      if value := string(radAttr.value) {
        return value
      }
      return ""
    case IPv4Addr:
      if value := BytesToIPv4String(radAttr.value) {
        return value
      }
      return ""
    case IPv4Prefix:
      // TODO: implement IPv4Prefix convertion
      return ""
    case IPv6Addr:
      if value := BytesToIPv6String(radAttr.value) {
        return value
      }
      return ""
    case IPv6Prefix:
      if value := BytesToIPv6String(radAttr.value) {
        return value
      }
      return ""
    case InterfaceId:
      // TODO: implement InterfaceID convertion
      return ""
    default:
      return ""
  }
}

// OriginalIntegerValue returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type
// integer or date
func (radAttr *RadiusAttribute) OriginalIntegerValue(allowedType SupportedAttributeTypes) uint32 {
  switch allowedType {
    case Integer:
      if value := BytesToInteger(radAttr.value) {
        return value
      }
      return 0
    case Date:
      if value := BytesToTimestamp(radAttr.value) {
        return value
      }
      return 0
    default:
      return 0
  }
}

// toBytes converts RadiusAttribute into uint8 slice
// so it could be sent over the network
func (radAttr *RadiusAttribute) toBytes() []uint8 {
  /*
   *
   *         0               1              2
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
     |     Type      |    Length     |  Value ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  *  Taken from https://tools.ietf.org/html/rfc2865#page-23
  */
  var output []uint8

  output = append(output, radAttr.id)
  output = append(output, uint8(len(radAttr.value)))
  output = append(output, radAttr.value...)

  return output
}

// RadiusPacket represents RADIUS packet
type RadiusPacket struct {
  id            uint8
  code          TypeCode
  authenticator []uint8
  attributes    []RadiusAttribute
}

func InitialisePacket(code TypeCode) RadiusPacket {
  return RadiusPacket {createPacketId(), code, createPacketAuthenticator(), []RadiusAttribute{}}
}

func InitialisePacketFromBytes(dictionary *Dictionary, bytes *[]uint8) RadiusPacket {
  var attributes []RadiusAttribute
 
  code := typeCodeFromUint8(bytes[0])
  id   := bytes[1]
  authenticator := bytes[4:20]

  lastIndex = 20

  for {
    if lastIndex == len(*bytes) { break }
    
    // TODO - process bytes to RadiusAttributes
  }

  return RadiusPacket {id, code, authenticator, attributes}
}

func createPacketId() uint8 {
  return uint8(rand.Intn(256))
}

func createPacketAuthenticator() []uint8 {
  var authenticator []uint8

  for i := 0; i < 16; i++ {
    authenticator = append(authenticator, uint8(rand.Intn(256)))
  }

  return authenticator
}
