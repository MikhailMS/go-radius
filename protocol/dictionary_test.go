package protocol

import (
  "testing"

  "github.com/stretchr/testify/assert"
)

func TestDictionaryFromFile(t *testing.T) {
  var attributes []DictionaryAttribute
  var values     []DictionaryValue
  var vendors    []DictionaryVendor


  dictPath      := "../dict_examples/test_dictionary_dict"
  dictionary, _ := DictionaryFromFile(dictPath)


  attributes = append(attributes, DictionaryAttribute{
    "User-Name",
    "",
    1,
    AsciiString,
  })

  attributes = append(attributes, DictionaryAttribute{
    "NAS-IP-Address",
    "",
    4,
    IPv4Addr,
  })

  attributes = append(attributes, DictionaryAttribute{
    "NAS-Port-Id",
    "",
    5,
    Integer,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Framed-Protocol",
    "",
    7,
    Integer,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Chargeable-User-Identity",
    "",
    89,
    ByteString,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Delegated-IPv6-Prefix",
    "",
    123,
    IPv6Prefix,
  })

  attributes = append(attributes, DictionaryAttribute{
    "MIP6-Feature-Vector",
    "",
    124,
    Integer64,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Mobile-Node-Identifier",
    "",
    145,
    ByteString,
  })

  attributes = append(attributes, DictionaryAttribute{
    "PMIP6-Home-Interface-ID",
    "",
    153,
    InterfaceId,
  })

  attributes = append(attributes, DictionaryAttribute{
    "PMIP6-Home-IPv4-HoA",
    "",
    155,
    IPv4Prefix,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Somevendor-Name",
    "Somevendor",
    1,
    AsciiString,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Somevendor-Number",
    "Somevendor",
    2,
    Integer,
  })

  attributes = append(attributes, DictionaryAttribute{
    "Class",
    "",
    25,
    ByteString,
  })



  values = append(values, DictionaryValue{
    "Framed-Protocol",
    "PPP",
    "",
    "1",
  })

  values = append(values, DictionaryValue{
    "Somevendor-Number",
    "Two",
    "Somevendor",
    "2",
  })


  vendors = append(vendors, DictionaryVendor{
    "Somevendor",
    10,
  })


  expectedDict := Dictionary{
    attributes,
    values,
    vendors,
  }

  assert.Equal(t, expectedDict, dictionary, "Dictionaries are not same!")
}
