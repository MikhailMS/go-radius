// RADIUS Generic Server implementation
package server

import (
  "crypto/md5"

  "github.com/MikhailMS/go-radius/protocol"
)

type Server struct {
  host         protocol.Host
  allowedHosts map[string]string
  server       string
  retries      uint16
  timeout      uint16
}


// RadiusServer interface specifies how to handle communication with RADIUS Client
type RadiusServer interface {
  // Run starts and keeps server running
  Run() error
  // HandleAuthRequest resolves AUTH RADIUS request
  HandleAuthRequest() ([]uint8, error)
  // HandleAcctRequest resolves ACCT RADIUS request
  HandleAcctRequest() ([]uint8, error)
  // HandleCoaRequest resolves COA RADIUS request
  HandleCoaRequest() ([]uint8, error)
}


// InitialiseClient initialises client
//
// Please note that you would need to call **SetPort** manually to initialise Client in full
func InitialiseServer(dictionary protocol.Dictionary, allowedHosts map[string]string, server string, retries uint16, timeout uint16) Server {
  host := protocol.CreateHostWithDictionary(dictionary)

  return Server { host, allowedHosts, server, retries, timeout }
}

// **Required/Optional**
//
// SetPort sets remote port, that responsible for specific RADIUS Message Type
func (server *Server) SetPort(msgType protocol.RadiusMsgType, port uint16) {
  server.host.SetPort(port, msgType)
}

// Port returns port of RADIUS server, that receives given type of RADIUS message/packet
func (server *Server) Port(typeCode protocol.TypeCode) (uint16, bool) {
  return server.host.Port(typeCode)
}

// AllowedHosts returns map of allowed hosts (Radius Clients) and their secrets
func (server *Server) AllowedHosts() map[string]string {
  return server.allowedHosts
}

// Server returns hostname/FQDN of RADIUS Server
func (server *Server) Server() string {
  return server.server
}

// Secret returns secret for a host
func (server *Server) Secret(host string) string {
  return server.allowedHosts[host]
}

// Retries returns retries
func (server *Server) Retries() uint16 {
  return server.retries
}

// Timeout returns timeout
func (server *Server) Timeout() uint16 {
  return server.timeout
}

// CreateReplyPacket creates RADIUS packet with any TypeCode without attributes
func (server *Server) CreateReplyPacket(replyCode protocol.TypeCode, attributes []protocol.RadiusAttribute, request *[]uint8, secret string) protocol.RadiusPacket {
  replyPacket := protocol.InitialiseRadPacket(replyCode)

  replyPacket.SetAttributes(attributes)
  replyPacket.OverrideID((*request)[1])

  replyBytes  := replyPacket.ToBytes()
  requestAuth := (*request)[4:20]

  authenticator := createReplyAuthenticator(secret, &replyBytes, &requestAuth)

  replyPacket.OverrideAuthenticator(authenticator)
  return replyPacket
}

// CreateAttributeByName creates RADIUS packet attribute by Name, that is defined in dictionary file
func (server *Server) CreateAttributeByName(attrName string, value *[]uint8) (protocol.RadiusAttribute, error) {
  return server.host.CreateAttributeByName(attrName, value)
}

// CreateAttributeByID creates RADIUS packet attribute by ID, that is defined in dictionary file
func (server *Server) CreateAttributeByID(attrID uint8, value *[]uint8) (protocol.RadiusAttribute, error) {
  return server.host.CreateAttributeByID(attrID, value)
}

// VerifyRequest verifies that incoming request is valid
//
// Server would try to build RadiusPacket from raw bytes, and if it succeeds then packet is
// valid, otherwise would return an Error
func (server *Server) VerifyRequest(packet *[]uint8) error {
  _, err := server.host.InitialisePacketFromBytes(packet)
  return err
}

// VerifyRequestAttributes verifies that incoming request's RadiusAttributes values are valid
//
// Server would try to build RadiusPacket from raw bytes, and then it would try to restore
// RadiusAttribute original value from bytes, based on the attribute data type, see [SupportedAttributeTypes](protocol::dictionary::SupportedAttributeTypes)
func (server *Server) VerifyRequestAttributes(packet *[]uint8) error {
  return server.host.VerifyPacketAttributes(packet)
}

// InitialisePacketFromBytes initialises RadiusPacket from bytes
//
// Unlike [VerifyRequest](Server::VerifyRequest), on success this function would return RadiusPacket
func (server *Server) InitialisePacketFromBytes(request *[]uint8) (protocol.RadiusPacket, error) {
  return server.host.InitialisePacketFromBytes(request)
}

// IsHostAllowed checks if host from where Server received RADIUS request is allowed host,
// meaning RADIUS Server can process such request
func (server *Server) IsHostAllowed(remoteHost string) bool {
  return server.allowedHosts[remoteHost] != ""
}

func createReplyAuthenticator(secret string, replyBytes *[]uint8, requestAuth *[]uint8) []uint8 {
  md5Hash := md5.New()

  md5Hash.Write((*replyBytes)[0:4]); // Append reply's   type code, reply ID and reply length
  md5Hash.Write(*requestAuth);        // Append request's authenticator
  md5Hash.Write((*replyBytes)[20:]); // Append reply's   attributes
  md5Hash.Write([]uint8(secret));    // Append server's  secret. Possibly it should be client's secret, which sould be stored together with allowed hostnames ?

  return md5Hash.Sum(nil)
}

