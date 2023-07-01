// Various helper functions, that are used by RADIUS Client & Server to encode/decode information
// inside RADIUS packet
// They are also available to crate users to prepare data before it is packed into RADIUS packet
package tools

import (
  "fmt"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// IPv6StringToBytes converts IPv6 Address string into vector of bytes
//
// Should be used for any Attribute of type **ipv6addr** or **ipv6prefix** to ensure value is encoded correctly
// Returns value & error, so need to check if any errors occured before using the value
func IPv6StringToBytes(ipv6 string) ([]uint8, error) {
  var ipv6Bytes []uint8
  processedIPv6 := strings.Split(ipv6, "/")

  if len(processedIPv6) == 2 {
    value, err := strconv.ParseUint(processedIPv6[1], 10, 8) // Doesn't really converts to uint8, require further cast
    if err != nil {
      return []uint8{}, err
    }

    ipv6Bytes = append(ipv6Bytes, 0, uint8(value))
  }

  ipv6Bytes = append(ipv6Bytes, net.ParseIP(processedIPv6[0])...)
  return ipv6Bytes, nil
}

// BytesToIPv6String converts IPv6 bytes into IPv6 string
// Returns value & bool => need to check bool, if true then successful, otherwise not
func BytesToIPv6String(ipv6 []uint8) (string, bool) {
  if len(ipv6) == 18 {
    var ipv6StringBuilder strings.Builder

    ipv6StringBuilder.WriteString(net.IP{ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15], ipv6[16], ipv6[17]}.String())
    ipv6StringBuilder.WriteString("/")
    ipv6StringBuilder.WriteString(strconv.FormatUint(uint64(ipv6[1]), 10))

    return ipv6StringBuilder.String(), true
  } else if len(ipv6) == 16 {
    return net.IP{ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]}.String(), true
  }

  return "", false
}

// IPv4StringToBytes converts IPv4 Address string into vector of bytes
//
// Should be used for any Attribute of type **ipaddr**, **ipv4addr** & **ipv4prefix** to ensure value is encoded correctly
// Returns value & error, so need to check if any errors occured before using the value
func IPv4StringToBytes(ipv4 string) ([]uint8, error) {
  var ipv4Bytes []uint8
  processedIPv4 := strings.Split(ipv4, "/")

  if len(processedIPv4) == 2 {
    value, err := strconv.ParseUint(processedIPv4[1], 10, 8) // Doesn't really converts to uint8, require further cast
    if err != nil {
      return []uint8{}, err
    }

    if value > 32 {
      return []uint8{}, errors.New(fmt.Sprintf("IPv4 Subnet must be no greater than 32, you provided %d", value))
    }

    ipv4Bytes = append(ipv4Bytes, 0, uint8(value))
  }

  ipv4Bytes = append(ipv4Bytes, net.ParseIP(processedIPv4[0])[12:]...)

  return ipv4Bytes, nil
}

// BytesToIPv4String converts IPv4 bytes into IPv4 string
func BytesToIPv4String(ipv4 []uint8) (string, error) {
  switch len(ipv4) {
  case 6:
    subnet     := binary.BigEndian.Uint16(ipv4[0:2])
    ipv4String := net.IPv4(ipv4[2], ipv4[3], ipv4[4], ipv4[5])

    return fmt.Sprintf("%s/%d", ipv4String.String(), subnet), nil
  case 4:
    ipv4String := net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
    return ipv4String.String(), nil
  default:
    return "", errors.New(fmt.Sprintf("Malformed IPv4: %v", ipv4))
  }
}

// IntegerToBytes converts u32 into vector of bytes
//
// Should be used for any Attribute of type **integer** to ensure value is encoded correctly
func IntegerToBytes(integer uint32) []uint8 {
  output := make([]uint8, 4)

  binary.BigEndian.PutUint32(output, integer)
  return output
}

// BytesToInteger converts integer bytes into u32
func BytesToInteger(integer []uint8) (uint32, bool) {
  if len(integer) != 4 {
    return 0, false
  }
  return binary.BigEndian.Uint32(integer), true
}

// Integer64ToBytes converts u64 into vector of bytes
//
// Should be used for any Attribute of type **integer** to ensure value is encoded correctly
func Integer64ToBytes(integer uint64) []uint8 {
  output := make([]uint8, 8)

  binary.BigEndian.PutUint64(output, integer)
  return output
}

// BytesToInteger64 converts integer bytes into u64
func BytesToInteger64(integer []uint8) (uint64, bool) {
  if len(integer) != 8 {
    return 0, false
  }
  return binary.BigEndian.Uint64(integer), true
}

// TimestampToBytes converts timestamp (int64) into vector of bytes
//
// Should be used for any Attribute of type **date** to ensure value is encoded correctly
// 
// Golang has timestamps as int64, however RADIIUS protocol expects timestamp('time') as uint32
// therefore we need to apply a bit of logic to link these 2 together
// Returns value & error, so need to check if any errors occured before using the value
func TimestampToBytes(timestamp int64) ([]uint8, error) {
  output := make([]uint8, 4)

  if timestamp > 0xFFFFFFFF {
    return []uint8{}, errors.New("Provided integer won't fit into uint32")
  }

  binary.BigEndian.PutUint32(output, uint32(timestamp))
  return output, nil
}

// BytesToTimestamp converts timestamp bytes into int64
//
// Golang has timestamps as int64, however RADIIUS protocol has timestamp('time') as uint32
// therefore we need to apply a bit of logic to link these 2 together
func BytesToTimestamp(timestamp []uint8) (uint32, bool) {
  if len(timestamp) != 4 {
    return 0, false
  }

  _tmp := binary.BigEndian.Uint32(timestamp)
	return _tmp, true
}


// EncryptData encrypts data since RADIUS packet is sent in plain text
//
// Should be used to encrypt value of **User-Password** attribute (but could also be used to
// encrypt any data)
func EncryptData(data, authenticator, secret *[]uint8) []uint8 {
  /* Step 1. Ensure that data buffer's length is multiple of 16
  *  Step 2. Construct hash:
  *
  *  On each iteration:
  *   1. read 16 elements from data
  *   2. calculate MD5 hash for: provided secret + (authenticator(on 1st iteration) or 16 elements of result from previous iteration (2nd+ iteration))
  *   3. execute bitwise XOR between each of 16 elements of MD5 hash and data buffer and record it in results vector
  *
  * Step 3. Return result vector
  */
  var result []uint8

  hash    := make([]uint8, 16)
  padding := 16 - len(*data) % 16

  initialData := make([]uint8, len(*data) + padding)
  
  copy(initialData[0:len(*data)], (*data)[:])
  copy(initialData[len(*data):],  hash[:padding])

  encryptHelper(&result, &initialData, authenticator, &hash, secret);
  return result
}

// DecryptData decrypts data since RADIUS packet is sent in plain text
//
// Should be used to decrypt value of **User-Password** attribute (but could also be used to
// decrypt any data)
func DecryptData(data, authenticator, secret *[]uint8) []uint8 {
  /* 
  * To decrypt the data, we need to apply the same algorithm as in encrypt_data()
  * but with small change
  *
  *  On each iteration:
  *   1. read 16 elements from data
  *   2. calculate MD5 hash for: provided secret + (authenticator(on 1st iteration) or 16 elements of data buffer from previous iteration (2nd+ iteration))
  *   3. execute bitwise XOR between each of 16 elements of MD5 hash and data buffer and record it in results vector
  *
  *  Once final result is generated, we need to pop all 0's from the end of the result slice
  *  It is safe to assume that data is always padded so it could be processed in the chunks of size 16
  */
  var result []uint8

  prevResult := make([]uint8, 16)
  hash       := make([]uint8, 16)

  copy(prevResult[:], (*authenticator)[:])

  for {
    md5Hash := md5.New()

    md5Hash.Write(*secret)
    md5Hash.Write(prevResult)

    copy(hash, md5Hash.Sum(nil))
    
    for i := 0; i < len(hash); i++ {
        hash[i] ^= (*data)[i]
    }

    result = append(result, hash...)

    copy(prevResult, (*data)[:16])
    *data = (*data)[16:]

    if len(*data) == 0 { break }
  }

  for {
    if result[len(result) - 1] == 0 {
      result = result[:len(result) - 1]
    } else { break }
  }
  
  return result
}

// SaltEncryptData encrypts data with salt since RADIUS packet is sent in plain text
//
// Should be used for RADIUS Tunnel-Password Attribute
func SaltEncryptData(data, authenticator, salt, secret *[]uint8) []uint8 {
  if len(*data) == 0 {
      return []uint8{}
  }

  var result      []uint8
  // Length = len(*data) + padding
  var initialData []uint8

  hash    := make([]uint8, 16)
  padding := 15 - len(*data) % 16

  saltedAuthenticator := make([]uint8, 18)

  result = append(result, (*salt)...)

  initialData = append(initialData, uint8(len(*data)))
  initialData = append(initialData, (*data)[:]...)
  initialData = append(initialData, hash[:padding]...)

  copy(saltedAuthenticator[:16], (*authenticator)[:16])
  copy(saltedAuthenticator[16:], (*salt)[:2])

  encryptHelper(&result, &initialData, &saltedAuthenticator, &hash, secret);
  return result
}

// SaltDecryptData decrypts data with salt since RADIUS packet is sent in plain text
//
// Should be used for RADIUS Tunnel-Password Attribute
func SaltDecryptData(data, authenticator, secret *[]uint8) ([]uint8, error) {
  /*
   * The salt decryption behaves almost the same as normal Password encryption in RADIUS
   * The main difference is the presence of a two byte salt, which is appended to the authenticator
  */
  initialLen := uint8(len(*data))

  if initialLen <= 1 {
    return []uint8{}, errors.New("salt encrypted attribute too short")
  }
  if initialLen <= 17 {
    // If len() equals to 3, it means that there is a Salt or there is a salt & data.len(): Both cases mean "Password is empty"
    // But for this function to actually work len() must be at least 18, otherwise we cannot
    // decrypt data as it is invalid
    return []uint8{}, nil
  }

  // Length = len(*data) - 2
  var result []uint8

  hash       := make([]uint8, 16)
  prevResult := make([]uint8, 18)

  copy(prevResult[:16], (*authenticator)[:16])
  copy(prevResult[16:], (*data)[:2])

  *data = (*data)[2:]
  
  for {
    md5Hash := md5.New()

    md5Hash.Write(*secret)
    md5Hash.Write(prevResult)

    copy(hash, md5Hash.Sum(nil))
    
    for i := 0; i < len(hash); i++ {
        hash[i] ^= (*data)[i]
    }

    result = append(result, hash...)

    prevResult = (*data)[:16]
    *data      = (*data)[16:]

    if len(*data) == 0 { break }
  }

  targetLen := result[0]
  result = result[1:]

  if targetLen > initialLen - 3 {
    return []uint8{}, errors.New("Tunnel Password is too long (shared secret might be wrong)")
  }

  return result[:targetLen], nil
}


func encryptHelper(output, data, authenticator, hash, secret *[]uint8) {
  tmp       := make([]uint8, 16)
  iteration := 1

  for {
    md5Hash := md5.New()

    md5Hash.Write(*secret)
    if iteration == 1 {
      md5Hash.Write(*authenticator)
    } else {
      md5Hash.Write(tmp)
    }
    
    copy(*hash, md5Hash.Sum(nil))
    iteration++

    for i := 0; i < len(*hash); i++ {
        (*data)[i] ^= (*hash)[i]
    }

    *output = append(*output, (*data)[:16]...)
    copy(tmp[:16], (*data)[:16])

    if len(*data) == 16 {
      *data = (*data)[:0]
    } else {
      *data = (*data)[16:]
    }

    if len(*data) == 0 { break }
  }
}
