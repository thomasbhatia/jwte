JWTe
=====
https://tools.ietf.org/html/rfc7518#
A light and compact yet fully IETF RFC 7518 compliant JSON Web Token (JWT) library for Erlang. 

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
- [x]  - secp512r1

* RSA PSS rsassa_pss_sign / rsassa_pss_verify

* None

Build
-----

    $ rebar3 compile

http://erlang.org/doc/apps/public_key/using_public_key.html
https://github.com/0x6e6562/otp_ecc/blob/master/src/otp_ecc.erl

Key generation:
* RSA: 
pri key: openssl genrsa -out rsa-2048_pri.pem 2048 
pub key: openssl rsa -in rsa-2048_pri.pem -pubout > rsa-2048_pub.pem

* EC 
decode: openssl ec -in ec-priv.pem -text -noout
"P-256" (openssl curve secp256k1)
"P-384" (openssl curve secp384k1)
"P-521" (openssl curve secp521k1)
Gen private key: 
	openssl ecparam -name secp256k1 -genkey -out ec_secp256k1_pri.pem 

Gen public key: 
	openssl ec -in ec-priv.pem -pubout -out ec-pub.pem

<!-- IETF says EC256, which is another name for secp256r1, e.g means secp256r1 and not secp256k1 (Koblitz curve, used in bitcoin) 
https://tools.ietf.org/html/rfc7518#section-3.4
-->
<!-- openssl ecparam -name secp256r1 -genkey -noout -out ec-secp256r1.pem -->
<!-- openssl ecparam -name secp384r1 -genkey -noout -out ec-secp384r1.pem -->
<!-- openssl ecparam -name secp521r1 -genkey -noout -out ec-secp521r1.pem -->



go() ->
    {_PubKey, PriKey} = crypto:generate_key(ecdh, secp256k1),
    SigBin = sign_message(PriKey, "Hello"),
    SigBin.

sign_message(PriKey, Msg) ->
    Algorithm = ecdsa,
    DigestType = sha256,
    MsgBin = list_to_binary(Msg),
    SigBin = crypto:sign(Algorithm, DigestType, MsgBin, [PriKey, secp256k1]),
    SigBin.


https://github.com/erlang/otp/blob/86d1fb0865193cce4e308baa6472885a81033f10/lib/public_key/test/public_key_SUITE.erl
Gen pri good: openssl ecparam -out ecdsa.pem -name sect571r1 -genkey
Gen pub good: openssl ec -in ecdsa.pem -pubout -out ecdsa.pub
rr(public_key).
<!-- {ok, ECPubPem} = file:read_file(filename:join(Datadir, "ec_pubkey.pem")),
    [{'SubjectPublicKeyInfo', _, _} = PubEntry0] =
        public_key:pem_decode(ECPubPem),
    ECPubKey = public_key:pem_entry_decode(PubEntry0).
 -->
%%Public key:
{ok, ECPubPem} = file:read_file("test/ec_sect571r1_pubkey.pem"),
    [{'SubjectPublicKeyInfo', _, _} = PubEntry0] =
        public_key:pem_decode(ECPubPem).
ECPubKey = public_key:pem_entry_decode(PubEntry0).

%%Private key:
{ok, ECPrivPem} = file:read_file("test/ec_sect571r1_prikey.pem").

[{'EcpkParameters', _, not_encrypted} = Entry1,
  {'ECPrivateKey', _, not_encrypted} = Entry2] = public_key:pem_decode(ECPrivPem).
ECPrivKey = public_key:pem_entry_decode(Entry2).

Msg = crypto:rand_bytes(32).

Signature = public_key:sign(Msg, sha512, ECPrivKey).

public_key:verify(Msg, sha512, Signature, ECPubKey).
======


1. Registered claims:
iss: The issuer of the token
sub: The subject of the token
aud: The audience of the token
exp: This will probably be the registered claim most often used. This will define the expiration in NumericDate value. The expiration MUST be after the current date/time.
nbf: Defines the time before which the JWT MUST NOT be accepted for processing
iat: The time the JWT was issued. Can be used to determine the age of the JWT
jti: Unique identifier for the JWT. Can be used to prevent the JWT from being replayed. This is helpful for a one time use token.

2. Public Claims
These are the claims that we create ourselves like user name, information, and other important information.

3. Private Claims
A producer and consumer may agree to use claim names that are private. These are subject to collision, so use them with caution.

