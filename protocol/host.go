// Shared base for RADIUS Client & Server implementations
package protocol

import (
  "fmt"
  "crypto/md5"
  "crypto/hmac"
  "errors"
)

const IGNORE_VERIFY_ATTRIBUTE = "Message-Authenticator"

// Generic struct that holds Server & Client common functions and attributes
type Host struct {
  authPort   uint16
  acctPort   uint16
  coaPort    uint16
  dictionary Dictionary
}

// CreateHostWithDictionary initialises host instance only with Dictionary;
// Ports should be set through *SetPort()*, otherwise default to 0
func CreateHostWithDictionary(dictionary Dictionary) Host {
  return Host { 0, 0, 0, dictionary }
}

// Initialises host instance with all required fields
func InitialiseHost(authPort, acctPort, coaPort uint16, dictionary Dictionary) Host {
  return Host { authPort, acctPort, coaPort, dictionary }
}

// SetPort sets remote port, that responsible for specific RADIUS Message Type
func (host *Host) SetPort(port uint16, radMsgType RadiusMsgType) bool {
  switch radMsgType {
    case AUTH:
      host.authPort = port
      return true
    case ACCT:
      host.acctPort = port
      return true
    case COA:
      host.coaPort = port
      return true
    default:
      return false
  }
}

// CreateAttributeByName creates RadiusAttribute with given name (name is checked against Dictionary)
func (host *Host) CreateAttributeByName(attributeName string, value *[]uint8) (RadiusAttribute, error) {
  radAttribute, ok := CreateRadAttributeByName(&host.dictionary, attributeName, value)
  if !ok {
    return RadiusAttribute{}, errors.New(fmt.Sprintf("Failed to create: %s attribute. Check if attribute exists in provided dictionary file", attributeName))
  }
  return radAttribute, nil
}

// CreateAttributeByID creates RadiusAttribute with given id (id is checked against Dictionary)
func (host *Host) CreateAttributeByID(attributeID uint8, value *[]uint8) (RadiusAttribute, error) {
  radAttribute, ok := CreateRadAttributeByID(&host.dictionary, attributeID, value)
  if !ok {
    return RadiusAttribute{}, errors.New(fmt.Sprintf("Failed to create: %d attribute. Check if attribute exists in provided dictionary file", attributeID))
  }
  return radAttribute, nil
}

// Port returns port of RADIUS server, that receives given type of RADIUS message/packet
func (host *Host) Port(code TypeCode) (uint16, bool) {
  switch code {
    case AccessRequest:
      return host.authPort, true
    case AccountingRequest:
      return host.acctPort, true
    case CoARequest:
      return host.coaPort, true
    default:
      return 0, false
  }
}

// Dictionary returns host's dictionary instance
func (host *Host) Dictionary() Dictionary {
  return host.dictionary
}

// DictionaryValueByAttrAndValueName returns VALUE from dictionary with given attribute & value name
func (host *Host) DictionaryValueByAttrAndValueName(attrName, valueName string) (DictionaryValue, bool) {
  for _, value := range host.dictionary.Values() {
    if value.Name() == valueName && value.AttributeName() == attrName {
      return value, true
    }
  }
  return DictionaryValue{}, false
}

// DictionaryAttributeByID returns ATTRIBUTE from dictionary with given id
func (host *Host) DictionaryAttributeByID(packetAttrID uint8) (DictionaryAttribute, bool) {
  for _, attr := range host.dictionary.Attributes() {
    if attr.Code() == packetAttrID {
      return attr, true
    }
  }
  return DictionaryAttribute{}, false
}

// DictionaryAttributeByName returns ATTRIBUTE from dictionary with given name
func (host *Host) DictionaryAttributeByName(packetAttrName string) (DictionaryAttribute, bool) {
  for _, attr := range host.dictionary.Attributes() {
    if attr.Name() == packetAttrName {
      return attr, true
    }
  }
  return DictionaryAttribute{}, false
}

// InitialisePacketFromBytes initialises RadiusPacket from bytes
func (host *Host) InitialiseRadiusPacketFromBytes(packet *[]uint8) (RadiusPacket, error) {
  return InitialiseRadiusPacketFromBytes(&host.dictionary, packet)
}

// VerifyPacketAttributes verifies that RadiusPacket attributes have valid values
//
// Note: doesn't verify Message-Authenticator attribute, because it is HMAC-MD5 hash, not an
// ASCII string
func (host *Host) VerifyPacketAttributes(packet *[]uint8) error {
  radPacket, err := InitialiseRadiusPacketFromBytes(&host.dictionary, packet)
  if err != nil {
    return err
  }

  for _, packetAttr := range radPacket.Attributes() {
    if packetAttr.Name() != IGNORE_VERIFY_ATTRIBUTE {
      dictAttribute, ok := host.DictionaryAttributeByID(packetAttr.ID())
      if !ok {
        return errors.New(fmt.Sprintf("Attribute with ID %d may not exist in provided dictionary file, thus verification failed", packetAttr.ID()))
      }

      dictAttrDataType := dictAttribute.CodeType()

      if !packetAttr.VerifyOriginalValue(dictAttrDataType) {
        return errors.New(fmt.Sprintf("Cannot verify original value of attribute with ID %d", packetAttr.ID()))
      }
    }
  }
  return nil
}

// VerifyMessageauthenticator verifies Message-Authenticator value
func (host *Host) VerifyMessageAuthenticator(secret string, packet *[]uint8) error {
  // Step 1. Get Message-Authenticator from packet
  radPacket, err := InitialiseRadiusPacketFromBytes(&host.dictionary, packet)
  if err != nil {
    return err
  }

  originalMsgAuth, err := radPacket.MessageAuthenticator()
  if err != nil {
    return err
  }

  // Step 2. Set Message-Authenticator in packet to [0; 16]
  zeroedAuthenticator := make([]uint8, 16)
  radPacket.OverrideMessageAuthenticator(zeroedAuthenticator)

  // Step 3. Calculate HMAC-MD5 for the packet
  packetBytes, ok := radPacket.ToBytes()
  if !ok {
    return errors.New("Failed to convert RadiusPacket to bytes")
  }

  calculatedHash := hmac.New(md5.New, []uint8(secret))
  calculatedHash.Write(packetBytes)

  // Step 4. Compare calculated hash with the one extracted in Step 1
  if hmac.Equal(originalMsgAuth, calculatedHash.Sum(nil)) {
    return nil
  }
  return errors.New("Packet Message-Authenticator mismatch")
}

