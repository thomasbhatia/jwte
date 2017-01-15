JWTe
=====
https://tools.ietf.org/html/rfc7518#
A light and compact yet fully IETF RFC 7518 compliant JSON Web Token (JWT) library for Erlang. 

Supports the following algorithms:

* HMAC with SHA-2
* HS256
* HS384
* HS512

* RSA PKCS1-v1_5 rsassa_pkcs1_sign / rsassa_pkcs1_verify
* RS256
* RS384
* RS512

* ECDSA rsaes_pkcs1_encrypt / rsaes_pkcs1_verify
* ES256 - secp256r1
* ES384 - secp384r1
* ES512 - secp512r1

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




{<<4,239,103,184,119,160,102,120,17,105,177,250,59,248,247,172,228,22,102,68,
   228,108,235,180,1,63,128,134,90,26,155,111,222,25,238,112,110,228,228,156,
   142,204,251,186,113,66,210,73,233,118,10,97,106,134,91,37,79,177,212,151,
   140,11,7,34,49>>,
 <<210,229,50,17,40,43,215,233,217,165,209,143,226,11,89,148,125,71,102,68,
   243,165,32,225,171,130,172,58,153,18,249,64>>}


 {ok, ECPriPem} = file:read_file("test/eckey_secp256k1_pri.pem"). 


MHQCAQEEIFuQlQk6t4Tu1C2DG/5+0sTA8akXYnq6ceuohDLzE5C3oAcGBSuBBAAK
oUQDQgAEFL+hSPIHK79NLNvZjLfGoQCM8tavfH7xGP8ddjUwgJSLyFL9CrlJJjSM
QsV1KgEfYDBi1QAHKdir3taRLujCXA==


{ok, PrivateBin} = file:read_file("test/ecdsa.pem").
{ok, PublicBin} = file:read_file("test/ecdsa.pub").
[SPKI] = public_key:pem_decode(PublicBin).

#'SubjectPublicKeyInfo'{algorithm = Der} = SPKI.
RealSPKI = public_key:der_decode('SubjectPublicKeyInfo', Der).


#'SubjectPublicKeyInfo'{algorithm = #'AlgorithmIdentifier'{ parameters = Params}} = RealSPKI.

#'SubjectPublicKeyInfo'{algorithm = #'AlgorithmIdentifier'{algorithm = {1,
                                                                        2,840,10045,2,1},
                                                           parameters = <<6,5,43,129,4,0,39>>},
                        subjectPublicKey = <<4,0,234,220,143,230,205,196,101,37,
                                             26,184,106,202,176,195,61,137,53,
                                             193,31,128,105,248,186,175,...>>}
