# JWTe

[![Travis](https://img.shields.io/travis/devinus/jwte.svg?style=flat-square)](https://travis-ci.org/thomasbhatia/jwte)
[![Hex.pm](https://img.shields.io/hexpm/v/jwte.svg?style=flat-square)](https://hex.pm/packages/jwte)
[![Hex.pm](https://img.shields.io/hexpm/dt/jwte.svg?style=flat-square)](https://hex.pm/packages/jwte)

A light and compact yet ***fully [IETF RFC 7518][1] compliant*** JSON Web Token (JWT) library for Erlang. 

Supports the following algorithms:

* HMAC with SHA-2
- [x] HS256
- [x] HS384
- [x] HS512

* RSA PKCS1-v1_5 rsassa_pkcs1_sign / rsassa_pkcs1_verify
- [x] RS256
- [x] RS384
- [x] RS512

* ECDSA rsaes_pkcs1_encrypt / rsaes_pkcs1_verify
- [x] ES256 - secp256r1
- [x] ES384 - secp384r1
- [x] ES512 - secp512r1


##Installation

Add JWTe to your ```rebar.config``` dependencies:

    {deps, [
        {jwte,{git , "git@github.com:thomasbhatia/jwte.git", {tag, "v0.5.0"}}}
    ]}.

##Usage
####Encode
    jwte:encode(#{foo => bar}, Key).

####Decode
Decode payload with verification

    jwte:decode(<<"XXXX">>, Key).

####Peek
Decode without verifying the payload

    jwte:peek(<<"XXXX">>).

##License

JWTe is released under [BSD][2] (see [`LICENSE`](LICESNE)).

[1]: https://tools.ietf.org/html/rfc7518#
[2]: https://opensource.org/licenses/BSD-2-Clause
