// RADIUS Packet implementation
package protocol

import (
  "errors"
  "fmt"
  "log"

  "crypto/hmac"
  "crypto/md5"
  "encoding/binary"
  "math/rand"
  "unicode/utf8"

  "github.com/MikhailMS/go-radius/tools"
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

func typeCodeFromUint8(code uint8) (TypeCode, bool) {
  switch code {
    case 1:
      return AccessRequest, true
    case 2:
      return AccessAccept, true
    case 3:
      return AccessReject, true
    case 4:
      return AccountingRequest, true
    case 5:
      return AccountingResponse, true
    case 11:
      return AccessChallenge, true
    case 12:
      return StatusServer, true
    case 13:
      return StatusClient, true
    case 40:
      return DisconnectRequest, true
    case 41:
      return DisconnectACK, true
    case 42:
      return DisconnectNAK, true
    case 43:
      return CoARequest, true
    case 44:
      return CoAACK, true
    case 45:
      return CoANAK, true
    default:
      return 0, false
  }
}

func typeCodeToUint8(code TypeCode) (uint8, bool) {
  switch code {
    case AccessRequest:
      return 1, true
    case AccessAccept:
      return 2, true
    case AccessReject:
      return  3, true
    case AccountingRequest:
      return  4, true
    case AccountingResponse:
      return 5, true
    case AccessChallenge:
      return 11, true
    case StatusServer:
      return 12, true
    case StatusClient:
      return 13, true
    case DisconnectRequest:
      return 40, true
    case DisconnectACK:
      return 41, true
    case DisconnectNAK:
      return 42, true
    case CoARequest:
      return 43, true
    case CoAACK:
      return 44, true
    case CoANAK:
      return 45, true
    default:
      return 0, false
  }
}

// RadiusAttribute represents an attribute, which would be sent to RADIUS Server/client as a part of RadiusPacket
type RadiusAttribute struct {
  id    uint8
  name  string
  value []uint8
}

// CreateRadAttributeByName creates RadiusAttribute with given name
//
// Returns nil if ATTRIBUTE with such name is not found in Dictionary
func CreateRadAttributeByName(dictionary *Dictionary, attributeName string, value *[]uint8) (RadiusAttribute, bool) {
  for _, attr := range dictionary.Attributes() {
    if attr.Name() == attributeName {
      return RadiusAttribute {attr.Code(), attributeName, *value}, true
    }
  }

  return RadiusAttribute{}, false
}

// CreateRadAttributeByID creates RadiusAttribute with given id
//
// Returns nil if ATTRIBUTE with such id is not found in Dictionary
func CreateRadAttributeByID(dictionary *Dictionary, attributeID uint8, value *[]uint8) (RadiusAttribute, bool) {
  for _, attr := range dictionary.Attributes() {
    if attr.Code() == attributeID {
      return RadiusAttribute {attributeID, attr.Name(), *value}, true
    }
  }

  return RadiusAttribute{}, false
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
      return utf8.Valid(radAttr.value)
    case ByteString:
      if string(radAttr.value) != "" {
        return true
      }
      return false
    case Integer:
      _, ok := tools.BytesToInteger(radAttr.value)
      if ok {
        return true
      }
      return false
    case Date:
      _, ok := tools.BytesToTimestamp(radAttr.value)
      if ok {
        return true
      }
      return false
    case IPv4Addr:
      value, _ := tools.BytesToIPv4String(radAttr.value)
      if value  != "" {
        return true
      }
      return false
    case IPv6Addr:
      _, ok := tools.BytesToIPv6String(radAttr.value)
      if ok {
        return true
      }
      return false
    case IPv6Prefix:
      _, ok := tools.BytesToIPv6String(radAttr.value)
      if ok {
        return true
      }
      return false
    default:
      return false
  }
}

// OriginalStringValue returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type string, ipaddr,
// ipv6addr or ipv6prefix
func (radAttr *RadiusAttribute) OriginalStringValue(allowedType SupportedAttributeTypes) (string, bool) {
  switch allowedType {
    case AsciiString:
      ok := utf8.Valid(radAttr.value)
      if !ok {
        return "", false
      }
      return string(radAttr.value), true
    case IPv4Addr:
      value, err := tools.BytesToIPv4String(radAttr.value)
      if err != nil {
        return "", false
      }
      return value, true
    case IPv6Addr:
      return tools.BytesToIPv6String(radAttr.value)
    case IPv6Prefix:
      return tools.BytesToIPv6String(radAttr.value)
    default:
      return "", false
  }
}

// OriginalIntegerValue returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type
// integer or date
func (radAttr *RadiusAttribute) OriginalIntegerValue(allowedType SupportedAttributeTypes) (uint32, bool) {
  switch allowedType {
    case Integer:
      return tools.BytesToInteger(radAttr.value)
    case Date:
      return tools.BytesToTimestamp(radAttr.value)
    default:
      return 0, false
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
  output = append(output, uint8(2 + len(radAttr.value)))
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
func InitialiseRadiusPacket(code TypeCode) RadiusPacket {
  return RadiusPacket {createPacketId(), code, createPacketAuthenticator(), []RadiusAttribute{}}
}

// InitialisePacketFromBytes initialises RADIUS packet from raw bytes
func InitialiseRadiusPacketFromBytes(dictionary *Dictionary, bytes *[]uint8) (RadiusPacket, error) {
  var attributes []RadiusAttribute
 
  code, ok := typeCodeFromUint8((*bytes)[0])
  if !ok {
    return RadiusPacket{}, errors.New("Invalid TypeCode")
  }
  id   := (*bytes)[1]
  authenticator := (*bytes)[4:20]

  lastIndex := 20

  for {
    if lastIndex == len(*bytes) { break }
    
    attrID     := (*bytes)[lastIndex]
    attrLength := int((*bytes)[lastIndex + 1])
    attrValue  := (*bytes)[(lastIndex + 2):(lastIndex + attrLength)]

    _tmpAttr, ok := CreateRadAttributeByID(dictionary, attrID, &attrValue)
    if !ok {
      return RadiusPacket{}, errors.New(fmt.Sprintf("attribute with ID: %d is not found in dictionary", attrID))
    }
    attributes = append(attributes, _tmpAttr)
    lastIndex += attrLength
  }

  return RadiusPacket {id, code, authenticator, attributes}, nil
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
func (radPacket *RadiusPacket) OverrideMessageAuthenticator(newMessageAuth []uint8) error {
  for idx := range radPacket.attributes {
    attr := &radPacket.attributes[idx]
    if attr.Name() == "Message-Authenticator" {
      attr.OverrideValue(newMessageAuth)
      return nil
    }
  }

  return errors.New("Message-Authenticator attribute not found in packet")
}

// Generates HMAC-MD5 hash for Message-Authenticator attribute
//
// Note 1: this function assumes that RadiusAttribute Message-Authenticator already exists in RadiusPacket
// Note 2: Message-Authenticator in RadiusPacket would be overwritten when this function is called
func (radPacket *RadiusPacket) GenerateMessageAuthenticator(secret string) error {
  // Step 1. Set Message-Authenticator to an array of 16 zeros in the RadiusPacket
  zeroedAuthenticator := make([]uint8, 16)

  err := radPacket.OverrideMessageAuthenticator(zeroedAuthenticator)
  if err != nil {
    return err
  }

  // Step 2. Calculate HMAC-MD5 for the entire RadiusPacket
  packetBytes, ok := radPacket.ToBytes()
  if !ok {
    return errors.New("failed to convert RadiusPacket to bytes")
  }

  hash := hmac.New(md5.New, []uint8(secret))
  hash.Write(packetBytes)

  // Step 3. Set Message-Authenticator to the result of Step 2
  err = radPacket.OverrideMessageAuthenticator(hash.Sum(nil))
  if err != nil {
    return err
  }

  return nil
}

// MessageAuthenticator returns Message-Authenticator value, if exists in RadiusPacket
// otherwise returns an error
func (radPacket *RadiusPacket) MessageAuthenticator() ([]uint8, error) {
  for _, attr := range radPacket.attributes {
    if attr.Name() == "Message-Authenticator" {
      return attr.value, nil
    }
  }

  return nil, errors.New("Message-Authenticator attribute not found in packet")
}

// ID returns RadiusPacket id
func (radPacket *RadiusPacket) ID() uint8 {
  return radPacket.id
}

// Authenticator returns RadiusPacket authenticator
func (radPacket *RadiusPacket) Authenticator() []uint8 {
  return radPacket.authenticator
}

// Code returns RadiusPacket code
func (radPacket *RadiusPacket) Code() TypeCode {
  return radPacket.code
}

// Attributes returns RadiusPacket attributes
func (radPacket *RadiusPacket) Attributes() []RadiusAttribute {
  return radPacket.attributes
}

// AttributeByName returns RadiusAttribute with given name
func (radPacket *RadiusPacket) AttributeByName(attrName string) RadiusAttribute {
  for _, attr := range radPacket.attributes {
    if attr.Name() == attrName {
      return attr
    }
  }

  return RadiusAttribute{}
}

// AttributeByID returns RadiusAttribute with given id
func (radPacket *RadiusPacket) AttributeByID(attrID uint8) RadiusAttribute {
  for _, attr := range radPacket.attributes {
    if attr.ID() == attrID {
      return attr
    }
  }

  return RadiusAttribute{}
}

// ToBytes converts RadiusPacket into ready-to-be-sent bytes slice
func (radPacket *RadiusPacket) ToBytes() ([]uint8, bool) {
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

  for _, attr := range radPacket.attributes {
    packetAttr = append(packetAttr, attr.toBytes()...)
  }

  code, ok := typeCodeToUint8(radPacket.code)
  if !ok {
    log.Println("WARNING: encountered invalid TypeCode when converting RadiusPacket to bytes")
    return []uint8{}, false
  }
  packetBytes = append(packetBytes, code)
  packetBytes = append(packetBytes, radPacket.id)
  packetBytes = append(packetBytes, packetLengthToBytes(uint16(20 + len(packetAttr)))...)
  packetBytes = append(packetBytes, radPacket.authenticator...)
  packetBytes = append(packetBytes, packetAttr...)

  return packetBytes, true
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
  bytes := make([]byte, 2)

  binary.BigEndian.PutUint16(bytes, length)
  return bytes
}
