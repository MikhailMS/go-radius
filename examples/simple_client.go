//go:build examples
// +build examples

// go run examples/simple_client.go

// Package examples provides basic examples on how to use go-radius package
package main

import (
  "fmt"
  "log"
  "net"

  "github.com/MikhailMS/go-radius/client"
  "github.com/MikhailMS/go-radius/protocol"
  "github.com/MikhailMS/go-radius/tools"
)

type RadiusClient struct {
  baseClient   client.Client
  radiusSocket *net.UDPAddr
}

func initialiseRadiusClient(authPort uint16, dictionary protocol.Dictionary, serverString string, secret string, retries uint16, timeout uint16, ) (RadiusClient, error) {
  radiusSocket, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", serverString, authPort))
  if err != nil {
    return RadiusClient{}, err
  }

  baseClient := client.InitialiseClient(dictionary, serverString, secret, retries, timeout)

  log.Println("--> Initialised RADIUS Client")
  return RadiusClient { baseClient, radiusSocket }, nil
}

func (client *RadiusClient) SendPacket(packet *[]uint8) error {
  conn, err := net.DialUDP("udp4", nil, client.radiusSocket)
  if err != nil {
    return err
  }
  defer conn.Close()
  
 n, err := conn.Write(*packet)
 if err != nil {
		log.Println("Failed to send RadiusPacket to server:", err)
		return err
	}

	log.Println(fmt.Sprintf("Sent %d bytes to server: %v", n, packet))
  return nil
}


func main() {
  log.Println("Starting RADIUS Client example")

  dictPath        := "dict_examples/integration_dict"
  dictionary, err := protocol.DictionaryFromFile(dictPath)

  if err != nil {
    log.Println(err)
    return
  }

  client, _    := initialiseRadiusClient(1812, dictionary, "127.0.0.1", "secret", 2, 10)
  radiusPacket := client.baseClient.CreateAuthRadiusPacket()

  // Define attributes that would be sent to RADIUS Server
  calledSID         := []uint8("00-04-5F-00-0F-D1")
  callingSID        := []uint8("00-01-24-80-B3-9C")
  framedIPBytes, _  := tools.IPv4StringToBytes("10.0.0.100")
  ipv4Bytes,_       := tools.IPv4StringToBytes("192.168.0.1")
  msgAuthBytes      := make([]uint8, 16)
  nasID             := []uint8("trillian")
  nasIPBytes,_      := tools.IPv4StringToBytes("192.168.1.10")
  nasPortIDBytes    := tools.IntegerToBytes(0)
  userNameBytes     := []uint8("testing")

  userPasswordBytes := []uint8("very secure password, that noone is able to guess")
  auth   := radiusPacket.Authenticator()
  secret := []uint8(client.baseClient.Secret())
  userPasswordBytes = tools.EncryptData(&userPasswordBytes, &auth, &secret)

  calledSIDAttr,  _ := client.baseClient.CreateAttributeByName("Called-Station-Id",     &calledSID)
  callingSIDAttr, _ := client.baseClient.CreateAttributeByName("Calling-Station-Id",    &callingSID)
  framedIPAttr,   _ := client.baseClient.CreateAttributeByName("Framed-IP-Address",     &framedIPBytes)
  ipv4Attr, _       := client.baseClient.CreateAttributeByName("Framed-IP-Address",     &ipv4Bytes)
  nasIDAttr,      _ := client.baseClient.CreateAttributeByName("NAS-Identifier",        &nasID)
  nasIPAttr,      _ := client.baseClient.CreateAttributeByName("NAS-IP-Address",        &nasIPBytes)
  nasPortAttr,    _ := client.baseClient.CreateAttributeByName("NAS-Port-Id",           &nasPortIDBytes)
  msgAuthAttr, _    := client.baseClient.CreateAttributeByName("Message-Authenticator", &msgAuthBytes)
  userNameAttr, _   := client.baseClient.CreateAttributeByName("User-Name",             &userNameBytes)
  userPassAttr, _   := client.baseClient.CreateAttributeByName("Password",              &userPasswordBytes)

  attributes := []protocol.RadiusAttribute { calledSIDAttr, callingSIDAttr, framedIPAttr, ipv4Attr, nasIDAttr, nasIPAttr, nasPortAttr, msgAuthAttr, userNameAttr, userPassAttr }
  // =====================================================

  radiusPacket.SetAttributes(attributes)
  radiusPacket.GenerateMessageAuthenticator(client.baseClient.Secret())

  radiusBytes, _ := radiusPacket.ToBytes()
  client.SendPacket(&radiusBytes)
}
