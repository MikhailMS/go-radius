package protocol

import (
  "bufio"
  "fmt"
  "log"
  "os"
  "strconv"
  "strings"
)

const COMMENT_PREFIX = "#"

// Represents a list of supported data types
// as defined in RFC 2865 & RFC 8044 
type SupportedAttributeTypes int

const (
    // Go's String; RFC 8044 calls this "text" - UTF-8 text
    AsciiString SupportedAttributeTypes = iota
    // Go's [u8]; RFC 8044 calls this "string" (FreeRADIUS calls this "octets") - binary data as a sequence of undistinguished octets
    ByteString
    // Go's u32
    Integer
    // Go's u64
    Integer64
    // Go's u32; RFC 8044 calls this "time"
    Date
    // Go's \[u8;4\]
    IPv4Addr
    // Go's \[u8;5\]
    IPv4Prefix
    // Go's \[u8;16\]
    IPv6Addr
    // Go's \[u8;18\]
    IPv6Prefix
    // Go's \[u8;6\]; RFC 8044 calls this "ifid"
    InterfaceId
    // Go's u32
)

// =============================
// Represents an ATTRIBUTE from RADIUS dictionary file
type DictionaryAttribute struct {
  /*
   * |--------|   name  | code | code type |
   * ATTRIBUTE User-Name   1      string
  */
  name       string
  vendorName string
  code       uint8
  codeType   SupportedAttributeTypes
}

func (da DictionaryAttribute) Name() string {
  return da.name
}

func (da DictionaryAttribute) Code() uint8 {
  return da.code
}

func (da DictionaryAttribute) CodeType() SupportedAttributeTypes {
  return da.codeType
}

// =============================



// =============================
// Represents a VALUE from RADIUS dictionary file
type DictionaryValue struct {
  attributeName string
  valueName     string
  vendorName    string
  value         string
}

func (dv *DictionaryValue) Name() string {
  return dv.valueName
}

func (dv *DictionaryValue) AttributeName() string {
  return dv.attributeName
}

func (dv *DictionaryValue) Value() string {
  return dv.value
}
// =============================

// =============================
// Represents a VENDOR from RADIUS dictionary file
type DictionaryVendor struct {
  name string
  id   uint8
}
// =============================

// =============================
// Represents RADIUS dictionary
type Dictionary struct {
  attributes []DictionaryAttribute
  values     []DictionaryValue
  vendors    []DictionaryVendor
}

func DictionaryFromFile(filePath string) (Dictionary, error) {
  var attributes []DictionaryAttribute
  var values     []DictionaryValue
  var vendors    []DictionaryVendor 

  var vendorName string

  file, err := os.Open(filePath)
  if err != nil {
    return Dictionary{}, err
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    line := scanner.Text()
    if line != "" && !strings.HasPrefix(line, COMMENT_PREFIX) {
      parsedLine := strings.Fields(line)

      switch parsedLine[0] {
        case "ATTRIBUTE":
          parseAttribute(parsedLine, vendorName, &attributes)
        case "VALUE":
          parseValue(parsedLine, vendorName, &values)
        case "VENDOR":
          parseVendor(parsedLine, &vendors)
        case "BEGIN-VENDOR":
          vendorName = parsedLine[1]
        case "END-VENDOR":
          vendorName = ""
        default: continue          
      }
    }
  }

  if err := scanner.Err(); err != nil {
    return Dictionary{}, err
  }

  return Dictionary{ attributes, values, vendors }, nil
}

func (dict *Dictionary) Attributes() []DictionaryAttribute {
  return dict.attributes
}

func (dict *Dictionary) Values() []DictionaryValue {
  return dict.values
}

func (dict *Dictionary) Vendors() []DictionaryVendor {
  return dict.vendors
}
// =============================


func assignAttributeType(codeType string) (SupportedAttributeTypes, bool) {
  switch codeType {
    case "text":
      return AsciiString, true
    case "string":
      return ByteString, true
    case "integer":
      return Integer, true
    case "integer64":
      return Integer64, true
    case "time":
      return Date, true
    case "ipv4addr", "ipaddr":
      return IPv4Addr, true
    case "ipv4prefix":
      return IPv4Prefix, true
    case "ipv6addr":
      return IPv6Addr, true
    case "ipv6prefix":
      return IPv6Prefix, true
    case "ifid":
      return InterfaceId, true
    default:
      log.Println(fmt.Sprintf("WARNING: cannot assign attribute type {%s} becasue it is not supported", codeType))
      return 0, false
  }
}

func parseAttribute(parsedLine []string, vendorName string, attributes *[]DictionaryAttribute) {
  value, err := strconv.ParseUint(parsedLine[2], 10, 8) // Doesn't really converts to uint8, require further cast
  if err != nil {
    panic(err)
  }

  attrType, ok := assignAttributeType(parsedLine[3])
  if ok {
    *attributes = append(*attributes, DictionaryAttribute{parsedLine[1], vendorName, uint8(value), attrType})
  }
}

func parseValue(parsedLine []string, vendorName string, values *[]DictionaryValue) {
  *values = append(*values, DictionaryValue{parsedLine[1], parsedLine[2], vendorName, parsedLine[3]})
}

func parseVendor(parsedLine []string, vendors *[]DictionaryVendor) {
  value, err := strconv.ParseUint(parsedLine[2], 10, 8) // Doesn't really converts to uint8, require further cast
  if err != nil {
    panic(err)
  }

  *vendors = append(*vendors, DictionaryVendor{parsedLine[1], uint8(value)})
}
