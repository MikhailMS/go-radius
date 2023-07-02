//go:build examples
// +build examples

// go run examples/simple_server.go

// Package examples provides basic examples on how to use go-radius package
package main

import (
  "fmt"
  "log"
  "net"

  "github.com/MikhailMS/go-radius/protocol"
  "github.com/MikhailMS/go-radius/server"
  "github.com/MikhailMS/go-radius/tools"
)

type RadiusServer struct {
  baseServer server.Server
  authSocket *net.UDPAddr
  acctSocket *net.UDPAddr
  coaSocket  *net.UDPAddr
}

func initialiseRadiusServer(authPort uint16, acctPort uint16, coaPort uint16, dictionary protocol.Dictionary, serverString string, retries uint16, timeout uint16, allowedHosts map[string]string) (RadiusServer, error) {
  authSocket, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", serverString, authPort))
  if err != nil {
    return RadiusServer{}, err
  }

  acctSocket, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", serverString, acctPort))
  if err != nil {
    return RadiusServer{}, err
  }

  coaSocket, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", serverString, coaPort))
  if err != nil {
    return RadiusServer{}, err
  }

  baseServer := server.InitialiseServer(dictionary, allowedHosts, serverString, retries, timeout)

  log.Println("--> Initialised RADIUS Server")

  return RadiusServer { baseServer, authSocket, acctSocket, coaSocket }, nil
}


// Run starts and keeps server running
func (server *RadiusServer) Run() error {
  authConnect, err := net.ListenUDP("udp4", server.authSocket)
  if err != nil {
    return err
  }

  acctConnect, err := net.ListenUDP("udp4", server.acctSocket)
  if err != nil {
    return err
  }

  coaConnect, err  := net.ListenUDP("udp4", server.coaSocket)
  if err != nil {
    return err
  }

  go server.HandleAuthRequest(authConnect)
  go server.HandleAcctRequest(acctConnect)
  go server.HandleCoaRequest(coaConnect)

  log.Println("--> Started RADIUS Server UDP listeners")

  select {}
}


// HandleAuthRequest resolves AUTH RADIUS request
func (server *RadiusServer) HandleAuthRequest(conn *net.UDPConn) ([]uint8, error) {
  // Message buffer
  buffer := make([]uint8, 4096)

  ipv6Bytes,_  := tools.IPv6StringToBytes("fc66::1/64")
  ipv4Bytes,_  := tools.IPv4StringToBytes("192.168.0.1")
  nasIPBytes,_ := tools.IPv4StringToBytes("192.168.1.10")

  ipv6Attr, _  := server.baseServer.CreateAttributeByName("Framed-IPv6-Prefix", &ipv6Bytes)
  ipv4Attr, _  := server.baseServer.CreateAttributeByName("Framed-IP-Address",  &ipv4Bytes)
  nasIPAttr, _ := server.baseServer.CreateAttributeByName("NAS-IP-Address",     &nasIPBytes)

  attributes := []protocol.RadiusAttribute { ipv6Attr, ipv4Attr, nasIPAttr }

  defer conn.Close()

  for {
    _, addr, err := conn.ReadFromUDP(buffer)
    if err == nil {
      log.Println(fmt.Sprintf("----> Received AUTH message from %s", addr.IP.String()))

      if server.baseServer.IsHostAllowed(addr.IP.String()) {
        replyPacket, err := server.baseServer.CreateReplyPacket(protocol.AccessAccept, attributes, &buffer, server.baseServer.Secret(addr.IP.String()))

        if err == nil {
          replyBytes, ok := replyPacket.ToBytes()

          if ok {
            log.Println("----> Sending AUTH reply", replyBytes)
            conn.WriteMsgUDP(replyBytes, []uint8{}, addr)
          }
        }
      }
    }
  }
}

// HandleAcctRequest resolves ACCT RADIUS request
func (server *RadiusServer) HandleAcctRequest(conn *net.UDPConn) ([]uint8, error) {
  // Message buffer
  buffer := make([]uint8, 4096)

  ipv6Bytes,_  := tools.IPv6StringToBytes("fc66::1/64")
  ipv4Bytes,_  := tools.IPv4StringToBytes("192.168.0.1")

  ipv6Attr, _  := server.baseServer.CreateAttributeByName("Framed-IPv6-Prefix", &ipv6Bytes)
  ipv4Attr, _  := server.baseServer.CreateAttributeByName("Framed-IP-Address",  &ipv4Bytes)

  attributes := []protocol.RadiusAttribute { ipv6Attr, ipv4Attr }

  defer conn.Close()

  for {
    _, addr, err := conn.ReadFromUDP(buffer)
    if err == nil {
      log.Println(fmt.Sprintf("----> Received ACCT message from %s", addr.IP.String()))
      
      if server.baseServer.IsHostAllowed(addr.IP.String()) {
        replyPacket, err := server.baseServer.CreateReplyPacket(protocol.AccountingResponse, attributes, &buffer, server.baseServer.Secret(addr.IP.String()))

        if err == nil {
          replyBytes, ok := replyPacket.ToBytes()

          if ok {
            log.Println("----> Sending ACCT reply")
            conn.WriteMsgUDP(replyBytes, []uint8{}, addr)
          }
        }
      }
    }
  }
}

// HandleCoaRequest resolves COA RADIUS request
func (server *RadiusServer) HandleCoaRequest(conn *net.UDPConn) ([]uint8, error) {
  // Message buffer
  buffer := make([]uint8, 4096)

  ipv4Bytes,_  := tools.IPv4StringToBytes("192.168.0.1")
  ipv4Attr, _  := server.baseServer.CreateAttributeByName("Framed-IP-Address", &ipv4Bytes)

  attributes := []protocol.RadiusAttribute { ipv4Attr }

  defer conn.Close()

  for {
    _, addr, err := conn.ReadFromUDP(buffer)
    if err == nil {
      log.Println(fmt.Sprintf("----> Received CoA message from %s", addr.IP.String()))
      
      if server.baseServer.IsHostAllowed(addr.IP.String()) {
        replyPacket, err := server.baseServer.CreateReplyPacket(protocol.CoAACK, attributes, &buffer, server.baseServer.Secret(addr.IP.String()))

        if err == nil {
          replyBytes, ok := replyPacket.ToBytes()

          if ok {
            log.Println("----> Sending CoA reply")
            conn.WriteMsgUDP(replyBytes, []uint8{}, addr)
          }
        }
      }
    }
  }
}


func main() {
  log.Println("Starting RADIUS Server example")

  dictPath        := "dict_examples/integration_dict"
  dictionary, err := protocol.DictionaryFromFile(dictPath)

  if err != nil {
    log.Println(err)
    return
  }

  allowedHosts := map[string]string { "127.0.0.1": "secret" }
  server, _    := initialiseRadiusServer(1812, 1813, 3799, dictionary, "127.0.0.1", 2, 10, allowedHosts)

  server.Run()
}
