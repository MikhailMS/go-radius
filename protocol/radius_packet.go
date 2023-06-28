// RADIUS Packet implementation
package protocol

import (
  "crypto/md5"
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

// CreateRadAttributeByName creates RadiusAttribute with given name
//
// Returns nil if ATTRIBUTE with such name is not found in Dictionary
func CreateRadAttributeByName(dictionary *Dictionary, attributeName string, value *[]uint8) RadiusAttribute {
  for attr := range dictionary.Attributes() {
    if attr.Name() == attributeName {
      return RadiusAttribute {attr.Id, attributeName, *value}
    }
  }

  return nil
}

// CreateRadAttributeByID creates RadiusAttribute with given id
//
// Returns nil if ATTRIBUTE with such id is not found in Dictionary
func CreateRadAttributeByID(dictionary *Dictionary, attributeID string, value *[]uint8) RadiusAttribute {
  for attr := range dictionary.Attributes() {
    if attr.Code() == attributeID {
      return RadiusAttribute {attributeID, attr.Name(), *value}
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

// toBytes converts RadiusAttribute into ready-to-be-sent bytes slice
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

// InitialisePacket initialises RADIUS packet with random ID and authenticator
func InitialiseRadPacket(code TypeCode) RadiusPacket {
  return RadiusPacket {createPacketId(), code, createPacketAuthenticator(), []RadiusAttribute{}}
}

// InitialisePacketFromBytes initialises RADIUS packet from raw bytes
func InitialiseRadPacketFromBytes(dictionary *Dictionary, bytes *[]uint8) RadiusPacket {
  var attributes []RadiusAttribute
 
  code := typeCodeFromUint8(bytes[0])
  id   := bytes[1]
  authenticator := bytes[4:20]

  lastIndex = 20

  for {
    if lastIndex == len(*bytes) { break }
    
    attrID     := bytes[lastIndex]
    attrLength := int(bytes[lastIndex + 1])
    attrValue  := bytes[(lastIndex + 2):(lastIndex + attrLength)]

    attributes = append(attributes, CreateRadAttributeByID(dictionary, attrID, *attrValue))
    lastIndex += attrLength
  }

  return RadiusPacket {id, code, authenticator, attributes}
}

// SetAttributes sets attrbiutes for RadiusPacket
func (radPacket *RadiusPacket) SetAttributes(attr []RadiusAttribute) {
  radPacket.attributes = attr
}

// Overrides RadiusPacket id
func (radPacket *RadiusPacket) OverrideID(id uint8) {
  radPacket.id = id
}

// Overrides RadiusPacket authenticator
func (radPacket *RadiusPacket) OverrideAuthenticator(authenticator []uint8) {
  radPacket.authenticator = authenticator
}

// Overrides RadiusPacket Message-Authenticator
//
// Note: would fail if RadiusPacket has no Message-Authenticator attribute defined
func (radPacket *RadiusPacket) OverrideMessageAuthenticator(newMessageAuth []uint8) {
  for attr := range radPacket.attributes {
    if attr.name == "Message-Authenticator" {
      attr.OverrideValue(newMessageAuth)
    }
  }
}

// Generates HMAC-MD5 hash for Message-Authenticator attribute
//
// Note 1: this function assumes that RadiusAttribute Message-Authenticator already exists in RadiusPacket
// Note 2: Message-Authenticator in RadiusPacket would be overwritten when this function is called
func (radPacket *RadiusPacket) GenerateMessageAuthenticator(secret string) {
  // Step 1. Set Message-Authenticator to an array of 16 zeros in the RadiusPacket
  zeroedAuthenticator := make([]uint8, 16)
  radPacket.OverrideMessageAuthenticator(zeroedAuthenticator)

  // Step 2. Calculate HMAC-MD5 for the entire RadiusPacket
  md5Hash := md5.New()
  md5Hash.Write([]uint8(secret))
  md5Hash.Write(radPacket.ToBytes())

  // Step 3. Set Message-Authenticator to the result of Step 2
  radPacket.OverrideMessageAuthenticator(md5Hash.Sum(nil))
}

// MessageAuthenticator returns Message-Authenticator value, if exists in RadiusPacket
func (radPacket *RadiusPacket) MessageAuthenticator(attr []RadiusAttribute) []uint8 {
  for attr := range radPacket.attributes {
    if attr.name == "Message-Authenticator" {
      return attr.value
    }
  }

  return nil
}

// ID returns RadiusPacket id
func (radPacket *RadiusPacket) ID(attr []RadiusAttribute) {
  return radPacket.id
}

// Authenticator returns RadiusPacket authenticator
func (radPacket *RadiusPacket) Authenticator(attr []RadiusAttribute) {
  return radPacket.authenticator
}

// Code returns RadiusPacket code
func (radPacket *RadiusPacket) Code(attr []RadiusAttribute) {
  return radPacket.code
}

// Attributes returns RadiusPacket attributes
func (radPacket *RadiusPacket) Attributes(attr []RadiusAttribute) {
  return radPacket.attributes
}

// AttributeByName returns RadiusAttribute with given name
func (radPacket *RadiusPacket) AttributeByName(attrName string) RadiusAttribute {
  for attr := range radPacket.attributes {
    if attr.name == attrName {
      return attr
    }
  }

  return nil
}

// AttributeByID returns RadiusAttribute with given id
func (radPacket *RadiusPacket) AttributeByID(attrID uint8) RadiusAttribute {
  for attr := range radPacket.attributes {
    if attr.id == attrID {
      return attr
    }
  }

  return nil
}

// ToBytes converts RadiusPacket into ready-to-be-sent bytes slice
func (radPacket *RadiusPacket) ToBytes(attr []RadiusAttribute) []uint8 {
  /* Prepare packet for a transmission to server/client
   *
   *          0               1               2         3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Code      |  Identifier   |            Length             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                         Authenticator                         |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Attributes ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-
   * Taken from https://tools.ietf.org/html/rfc2865#page-14
   *
   */
  var packetBytes []uint8
  var packetAttr  []uint8

  if len(radPacket.authenticator) == 0 {
    radPacket.authenticator = createPacketAuthenticator()
  }

  for attr := range radPacket.attributes {
    packetAttr = append(packetAttr, attr.ToBytes()...)
  }

  packetBytes = append(packetBytes, radPacket.code)
  packetBytes = append(packetBytes, radPacket.id)
  packetBytes = append(packetBytes, packetLengthToBytes(uint16(20 + len(packetAttr)))...)
  packetBytes = append(packetBytes, radPacket.authenticator...)
  packetBytes = append(packetBytes, packetAttr...)

  return packetBytes
}


// createPacketId creates random uint8 ID for RadiusPacket
func createPacketId() uint8 {
  return uint8(rand.Intn(256))
}

// createPacketAuthenticator creates an uint8 slice of length 16
// filled with random numbers
func createPacketAuthenticator() []uint8 {
  var authenticator []uint8

  for i := 0; i < 16; i++ {
    authenticator = append(authenticator, uint8(rand.Intn(256)))
  }

  return authenticator
}

// packetLengthToBytes converts uint16 into []uint8 (of length 2)
func packetLengthToBytes(length uint16) []uint8 {
  return []uint8{ uint8(length), uint8(length >> 8) }
}
