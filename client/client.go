// RADIUS Generic Client implementation
package client

import (
  "errors"
  "fmt"
  "crypto/hmac"
  "crypto/md5"

  "github.com/MikhailMS/go-radius/protocol"
)

type Client struct {
  host           protocol.Host
  server         string
  secret         string
  retries        uint16
  timeout        uint16
}

// InitialiseClient initialises client
//
// Please note that you would need to call **SetPort** manually to initialise Client in full
func InitialiseClient(dictionary protocol.Dictionary, server string, secret string, retries uint16, timeout uint16) Client {
  host := protocol.CreateHostWithDictionary(dictionary)

  return Client { host, server, secret, retries, timeout }
}

// **Required/Optional**
//
// SetPort sets remote port, that responsible for specific RADIUS Message Type
func (client *Client) SetPort(msgType protocol.RadiusMsgType, port uint16) {
  client.host.SetPort(port, msgType)
}

// Port returns port of RADIUS server, that receives given type of RADIUS message/packet
func (client *Client) Port(typeCode protocol.TypeCode) (uint16, bool) {
  return client.host.Port(typeCode)
}

// Server returns hostname/FQDN of RADIUS Server
func (client *Client) Server() string {
  return client.server
}

// Secret returns secret
func (client *Client) Secret() string {
  return client.secret
}

// Retries returns retries
func (client *Client) Retries() uint16 {
  return client.retries
}

// Timeout returns timeout
func (client *Client) Timeout() uint16 {
  return client.timeout
}

// CreateRadiusPacket creates RADIUS packet with any TypeCode without attributes
//
// You would need to set attributes manually via *set_attributes()* function
func (client *Client) CreateRadiusPacket(typeCode protocol.TypeCode) protocol.RadiusPacket {
  return protocol.InitialiseRadPacket(typeCode)
}

// CreateAuthRadiusPacket creates RADIUS packet with AccessRequest TypeCode without attributes
//
// You would need to set attributes manually via *set_attributes()* function
func (client *Client) CreateAuthRadiusPacket() protocol.RadiusPacket {
  return protocol.InitialiseRadPacket(protocol.AccessRequest)
}

// CreateAcctRadiusPacket creates RADIUS packet with AccountingRequest TypeCode without attributes
//
// You would need to set attributes manually via *set_attributes()* function
func (client *Client) CreateAcctRadiusPacket() protocol.RadiusPacket {
  return protocol.InitialiseRadPacket(protocol.AccountingRequest)
}

// CreateCoaRadiusPacket creates RADIUS packet with CoARequest TypeCode without attributes
//
// You would need to set attributes manually via *set_attributes()* function
func (client *Client) CreateCoaRadiusPacket() protocol.RadiusPacket {
  return protocol.InitialiseRadPacket(protocol.CoARequest)
}

// CreateAttributeByName creates RADIUS packet attribute by Name, that is defined in dictionary file
func (client *Client) CreateAttributeByName(attrName string, value *[]uint8) (protocol.RadiusAttribute, error) {
  return client.host.CreateAttributeByName(attrName, value)
}

// CreateAttributeByID creates RADIUS packet attribute by ID, that is defined in dictionary file
func (client *Client) CreateAttributeByID(attrID uint8, value *[]uint8) (protocol.RadiusAttribute, error) {
  return client.host.CreateAttributeByID(attrID, value)
}

// RadiusAttrOriginalStringValue creates RADIUS packet attribute by ID, that is defined in dictionary file
func (client *Client) RadiusAttrOriginalStringValue(attribute protocol.RadiusAttribute) (string, error) {
  dictAttr, ok := client.host.DictionaryAttributeByID(attribute.ID())

  if !ok {
    return "", errors.New(fmt.Sprintf("No attribute with ID: %d found in dictionary", attribute.ID()))
  }

  attrOrigValue, ok := attribute.OriginalStringValue(dictAttr.CodeType())

  if !ok {
    return "", errors.New(fmt.Sprintf("Error while decoding original value of attribute with ID: %d", attribute.ID()))
  }

  return attrOrigValue, nil
}

// RadiusAttrOriginalIntegerValue creates RADIUS packet attribute by ID, that is defined in dictionary file
func (client *Client) RadiusAttrOriginalIntegerValue(attribute protocol.RadiusAttribute) (uint32, error) {
  dictAttr, ok := client.host.DictionaryAttributeByID(attribute.ID())

  if !ok {
    return 0, errors.New(fmt.Sprintf("No attribute with ID: %d found in dictionary", attribute.ID()))
  }

  attrOrigValue, ok := attribute.OriginalIntegerValue(dictAttr.CodeType())

  if !ok {
    return 0, errors.New(fmt.Sprintf("Error while decoding original value of attribute with ID: %d", attribute.ID()))
  }

  return attrOrigValue, nil
}

// InitialisePacketFromBytes creates RADIUS packet attribute by ID, that is defined in dictionary file
func (client *Client) InitialisePacketFromBytes(reply *[]uint8) (protocol.RadiusPacket, error) {
  return client.host.InitialisePacketFromBytes(reply)
}

// VerifyReply creates RADIUS packet attribute by ID, that is defined in dictionary file
func (client *Client) VerifyReply(request *protocol.RadiusPacket, reply *[]uint8) (bool, error) {
  if len(*reply) == 0 {
    return false, errors.New("Empty reply")
  }

  if request.ID() != (*reply)[1] {
    return false, errors.New("Packet identifier mismatch")
  }

  hmacHash := md5.New()

  hmacHash.Write((*reply)[0:4])           // Append reply type code, reply ID and reply length
  hmacHash.Write(request.Authenticator()) // Append request authenticator
  hmacHash.Write((*reply)[20:])           // Append rest of the reply
  hmacHash.Write([]uint8(client.secret))  // Append secret

  if hmac.Equal((*reply)[4:20], hmacHash.Sum(nil)) {
    return true, nil
  }
  return false, errors.New("Packet authenticator mismatch")

}

// VerifyMessageAuthenticator verifies that reply packet's Message-Authenticator attribute is valid
func (client *Client) VerifyMessageAuthenticator(packet *[]uint8) error {
  return client.host.VerifyMessageAuthenticator(client.secret, packet)
}

// VerifyPacketAttributes verifies that reply packet's attributes have valid values
func (client *Client) VerifyPacketAttributes(packet *[]uint8) error {
  return client.host.VerifyPacketAttributes(packet)
}
