package tools

import (
  "testing"

  "github.com/stretchr/testify/assert"
)

func TestIPv6ToBytesWoSubnet(t *testing.T) {
  expectedBytes := []uint8{ 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }
  
  ipv6Bytes := IPv6StringToBytes("fc66::1")
  assert.Equal(t, expectedBytes, ipv6Bytes, "IPv6 bytes are not correct!")
}

func TestBytesToIPv6StringWoSubnet(t *testing.T) {
  expectedString := "fc66::1"

  ipv6Bytes := []uint8{ 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }
  assert.Equal(t, expectedString, BytesToIPv6String(ipv6Bytes), "IPv6 string are not correct!")
}

func TestIPv6ToBytesWSubnet(t *testing.T) {
  expectedBytes := []uint8{ 0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }

  ipv6Bytes := IPv6StringToBytes("fc66::1/64")
  assert.Equal(t, expectedBytes, ipv6Bytes, "IPv6 bytes are not correct!")
}

func TestBytesToIPv6StringWSubnet(t *testing.T) {
  expectedString := "fc66::1/64"

  ipv6Bytes := []uint8{ 0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }
  assert.Equal(t, expectedString, BytesToIPv6String(ipv6Bytes), "IPv6 string are not correct!")
}

func TestIPv4StringToBytes(t *testing.T) {
  expectedBytes := []uint8{ 192, 1, 10, 1 }

  ipv4Bytes     := IPv4StringToBytes("192.1.10.1")
  assert.Equal(t, expectedBytes, ipv4Bytes, "IPv4 bytes are not correct!")
}

func TestIPv4BytesToString(t *testing.T) {
  expectedString := "192.1.10.1"

  ipv4String     := BytesToIPv4String([]uint8{ 192, 1, 10, 1 })
  assert.Equal(t, expectedString, ipv4String, "IPv4 string is not correct!")
}

func TestIntegerToBytes(t *testing.T) {
  expectedBytes := []uint8{ 0, 0, 39, 16 } 

  integer := uint32(10000)
  assert.Equal(t, expectedBytes, IntegerToBytes(integer), "Integer bytes is not correct!")
}

func TestBytesToInteger(t *testing.T) {
  expectedInteger := uint32(10000)

  integerBytes := []uint8{ 0, 0, 39, 16 } 
  assert.Equal(t, expectedInteger, BytesToInteger(integerBytes), "Integer is not correct!")
}

func TestTimestampToBytes(t *testing.T) {
  expectedBytes := []uint8 { 95, 71, 138, 29 }

  timestamp := int64(1598523933)
  assert.Equal(t, expectedBytes, TimestampToBytes(timestamp), "Timestamp bytes is not correct!")
}

func TestBytesToTimestamp(t *testing.T) {
  expectedTimestamp := int64(1598523933)

  timestampBytes := []uint8 { 95, 71, 138, 29 }
  assert.Equal(t, expectedTimestamp, BytesToTimestamp(timestampBytes), "Timestamp integer is not correct!")
}


func TestEncryptData(t *testing.T) {
  expectedBytes := []uint8{ 135, 116, 155, 239, 226, 89, 90, 221, 62, 29, 218, 130, 102, 174, 191, 250 }

  secret        := []uint8("secret")
  data          := []uint8("password")
  authenticator := []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

  encryptedBytes := EncryptData(&data, &authenticator, &secret)
  assert.Equal(t, expectedBytes, encryptedBytes, "Encrypted bytes are not correct!")
}

func TestEncryptDataLong(t *testing.T) {
  expectedBytes := []uint8{ 150, 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193,
                            149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200, 246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152,
                            63, 40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250,170, 105, 94, 20, 105, 120, 196, 237, 191, 99, 69 }

  secret        := []uint8("secret")
  data          := []uint8("a very long password, which will need multiple iterations")
  authenticator := []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

  encryptedBytes := EncryptData(&data, &authenticator, &secret)
  assert.Equal(t, expectedBytes, encryptedBytes, "Encrypted bytes are not correct!")
}

func TestEncryptDataLimitLong(t *testing.T) {
  expectedBytes := []uint8{ 150, 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193, 149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200,
                            246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152, 63, 40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250, 170, 105, 94, 20, 71,
                            88, 165, 205, 201, 6, 55, 222, 205, 192, 227, 172, 93, 166, 15, 33, 86, 56, 181, 52, 4, 49, 190, 186, 17, 125, 50, 140, 52, 130, 194,
                            125, 93, 177, 65, 217, 195, 23, 75, 175, 219, 244, 156, 133, 145, 20, 176, 36, 90, 16, 77, 148, 221, 251, 155, 9, 107, 213, 140, 107,
                            112, 161, 99, 6, 108, 106, 33, 69, 192, 191, 98, 30, 147, 197, 72, 160, 234, 50, 243, 195, 62, 72, 225, 19, 63, 28, 221, 164, 43, 67,
                            63, 206, 208, 124, 254, 202, 118, 229, 58, 180, 210, 100, 149, 120, 97, 23, 203, 197, 139, 244, 241, 175, 232, 149, 77, 43, 231, 27, 56,
                            250, 58, 251, 6, 203, 197, 190, 78, 83, 127, 164, 31, 211, 52, 74, 92, 36, 250, 236, 210, 72, 52, 55, 248, 161, 160, 95, 102, 63, 190, 43,
                            253, 224, 114, 62, 23, 11, 242, 186, 91, 132, 14, 76, 171, 26, 1, 51, 78, 144, 50, 228, 212, 47, 104, 98, 60, 245, 1, 103, 217, 49, 105,
                            38, 108, 93, 85, 224, 227, 33, 50, 144, 0, 233, 54, 174, 67, 174, 101, 189, 41 }

  secret        := []uint8("secret")
  data          := []uint8("a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long passw")
  authenticator := []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

  encryptedBytes := EncryptData(&data, &authenticator, &secret)
  assert.Equal(t, expectedBytes, encryptedBytes, "Encrypted bytes are not correct!")
}


func TestDecryptData(t *testing.T) {
  expectedData  := []uint8("password")
  
  secret        := []uint8("secret")
  authenticator := []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }
  encryptedData := []uint8{ 135, 116, 155, 239, 226, 89, 90, 221, 62, 29, 218, 130, 102, 174, 191, 250 }

  decryptedData := DecryptData(&encryptedData, &authenticator, &secret)
  assert.Equal(t, expectedData, decryptedData, "Decrypted data is not correct!")
}

func TestDecryptDataLong(t *testing.T) {
  expectedData  := []uint8("a very long password, which will need multiple iterations")
  
  secret        := []uint8("secret")
  authenticator := []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

  encryptedData := []uint8{ 150, 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193,
                            149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200, 246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152, 63,
                            40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250,170, 105, 94, 20, 105, 120, 196, 237, 191, 99, 69 }

  decryptedData := DecryptData(&encryptedData, &authenticator, &secret)
  assert.Equal(t, expectedData, decryptedData, "Decrypted data is not correct!")
}

func TestDecryptDataLimitLong(t *testing.T) {
  expectedData  := []uint8("a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long passw")
  
  secret        := []uint8("secret")
  authenticator := []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

  encryptedData := []uint8{ 150, 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193, 149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200,
                            246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152, 63, 40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250, 170, 105, 94, 20, 71,
                            88, 165, 205, 201, 6, 55, 222, 205, 192, 227, 172, 93, 166, 15, 33, 86, 56, 181, 52, 4, 49, 190, 186, 17, 125, 50, 140, 52, 130, 194,
                            125, 93, 177, 65, 217, 195, 23, 75, 175, 219, 244, 156, 133, 145, 20, 176, 36, 90, 16, 77, 148, 221, 251, 155, 9, 107, 213, 140, 107,
                            112, 161, 99, 6, 108, 106, 33, 69, 192, 191, 98, 30, 147, 197, 72, 160, 234, 50, 243, 195, 62, 72, 225, 19, 63, 28, 221, 164, 43, 67,
                            63, 206, 208, 124, 254, 202, 118, 229, 58, 180, 210, 100, 149, 120, 97, 23, 203, 197, 139, 244, 241, 175, 232, 149, 77, 43, 231, 27, 56,
                            250, 58, 251, 6, 203, 197, 190, 78, 83, 127, 164, 31, 211, 52, 74, 92, 36, 250, 236, 210, 72, 52, 55, 248, 161, 160, 95, 102, 63, 190, 43,
                            253, 224, 114, 62, 23, 11, 242, 186, 91, 132, 14, 76, 171, 26, 1, 51, 78, 144, 50, 228, 212, 47, 104, 98, 60, 245, 1, 103, 217, 49, 105,
                            38, 108, 93, 85, 224, 227, 33, 50, 144, 0, 233, 54, 174, 67, 174, 101, 189, 41 }

  decryptedData := DecryptData(&encryptedData, &authenticator, &secret)
  assert.Equal(t, expectedData, decryptedData, "Decrypted data is not correct!")
}

func TestSaltEncryptData(t *testing.T) {
  encryptedData := []uint8{ 0x85, 0x9a, 0xe3, 0x88, 0x34, 0x49, 0xf2, 0x1e, 0x14, 0x4c, 0x76, 0xc8, 0xb2, 0x1a, 0x1d, 0x4f, 0x0c, 0xdc }

  secret        := []uint8("secret")
  plaintext     := []uint8("password")
  salt          := encryptedData[:2]
  authenticator := make([]uint8, 16)

  assert.Equal(t, encryptedData, SaltEncryptData(&plaintext, &authenticator, &salt, &secret), "SaltEncryptData data is not correct!")
}

func TestSaltEncryptDataLongData(t *testing.T) {
  encryptedData := []uint8{ 0x85, 0xd9, 0x61, 0x72, 0x75, 0x37, 0xcf, 0x15, 0x20,
    0x19, 0x3b, 0x38, 0x39, 0x0e, 0x42, 0x21, 0x9b, 0x5e, 0xcb, 0x93, 0x25, 0x7d, 0xb4, 0x07,
    0x0c, 0xc1, 0x52, 0xcf, 0x38, 0x76, 0x29, 0x02, 0xc7, 0xb1, 0x29, 0xdf, 0x63, 0x96, 0x26,
    0x1a, 0x27, 0xe5, 0xc3, 0x13, 0x78, 0xa7, 0x97, 0xd8, 0x97, 0x9a, 0x45, 0xc3, 0x70, 0xd3,
    0xe4, 0xe2, 0xae, 0xd0, 0x55, 0x77, 0x19, 0xa5, 0xb6, 0x44, 0xe6, 0x8a }
  
  secret        := []uint8("secret")
  authenticator := make([]uint8, 16)
  plaintext     := []uint8("a very long password, which will need multiple iterations")
  salt          := encryptedData[:2]

  assert.Equal(t, encryptedData, SaltEncryptData(&plaintext, &authenticator, &salt, &secret), "SaltEncryptData data is not correct!")
}

func TestSaltDecryptData(t *testing.T) {
  encryptedData := []uint8{ 0x85, 0x9a, 0xe3, 0x88, 0x34, 0x49, 0xf2, 0x1e, 0x14, 0x4c, 0x76, 0xc8, 0xb2, 0x1a, 0x1d, 0x4f, 0x0c, 0xdc }
  
  secret        := []uint8("secret")
  authenticator := make([]uint8, 16)
  plaintext     := []uint8("password")

  assert.Equal(t, plaintext, SaltDecryptData(&encryptedData, &authenticator, &secret), "SaltDecryptData data is not correct!")
}

func TestSaltDecryptDataLongData(t *testing.T) {
  encryptedData := []uint8{ 0x85, 0xd9, 0x61, 0x72, 0x75, 0x37, 0xcf, 0x15, 0x20,
    0x19, 0x3b, 0x38, 0x39, 0x0e, 0x42, 0x21, 0x9b, 0x5e, 0xcb, 0x93, 0x25, 0x7d, 0xb4, 0x07,
    0x0c, 0xc1, 0x52, 0xcf, 0x38, 0x76, 0x29, 0x02, 0xc7, 0xb1, 0x29, 0xdf, 0x63, 0x96, 0x26,
    0x1a, 0x27, 0xe5, 0xc3, 0x13, 0x78, 0xa7, 0x97, 0xd8, 0x97, 0x9a, 0x45, 0xc3, 0x70, 0xd3,
    0xe4, 0xe2, 0xae, 0xd0, 0x55, 0x77, 0x19, 0xa5, 0xb6, 0x44, 0xe6, 0x8a }
  
  secret        := []uint8("secret")
  authenticator := make([]uint8, 16)
  plaintext     := []uint8("a very long password, which will need multiple iterations")

  assert.Equal(t, plaintext, SaltDecryptData(&encryptedData, &authenticator, &secret), "SaltDecryptData data is not correct!")
}
