=============
# v0.2.0 (02 Jul 2023)

This is first complete release of `go-radius` package

## What's new
* `client` module:
    * Generic implementation of RadiusClient
* `protocol` module:
    * Implemented parse of dictionary files
    * Support for all core data types:
        * text
        * string
        * integer
        * integer64
        * time
        * ipaddr
        * ipv4addr
        * ipv4prefix
        * ipv6addr
        * ipv6prefix
        * ifid
    * Support for all Type Codes - as per `RFC 2865` & `RFC 3576`
    * All required functions to support work with Radius Packets
* `server` module:
    * Generic implementation of RadiusServer
* `tools` module:
    * Helpers to work with all core data types:
        * Integer to bytes and vice versa
        * Integer64 to bytes and vice versa
        * Time to bytes and vice versa
        * IPAddr, IPv4Addr & IPv4Prefix to bytes and vice versa
        * IPv6Addr & IPv6Prefix to bytes and vice versa
        * Ifid to bytes and vice versa
    * Helpers to encrypt/decrypt data (including salted)
* `examples` module:
    * Example for Radius Server
    * Example for Radius Client

## What's removed or deprecated

## What's changed
