%% Supports HMAC, RSA, EC. TODO: Pass atom instead of Binary Algorithm. Add lager support.
%% Pass records or map instead of this crap
%% use verify_strict?

-module(jwte).

-include("jwte.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API exports
-export([peek/1, sign/2, sign/3, verify/2, verify/3]).

%%====================================================================
%% API functions
%%====================================================================
peek(JWT) ->
    verify(JWT, undefined).

sign(Claims, Key) ->
    sign(#{claims => Claims, key => Key}).

sign(Claims, Key, Alg) ->
    sign(#{claims => Claims, key => Key, alg => Alg}).

sign(#{claims := _Claims, key := _Key} = Payload0) when (map_size(Payload0) =:= 2) ->
    Payload = Payload0#{alg => <<"HS256">>},
    sign(Payload);

sign(#{claims := Claims, key := Key, alg := Alg}) ->
    Header = [{<<"alg">>, Alg}, {<<"typ">>, <<"JWT">>}],
    Hjson = jsx:encode(Header),
    Pjson = jsx:encode(Claims),
    Hb = base64url:encode(Hjson),
    Pb = base64url:encode(Pjson),
    UnsignedToken = <<Hb/binary, ".", Pb/binary>>,
    SigType = get_signature_type(Alg),
    Signer = signer(SigType, Key, UnsignedToken),
    Signed = base64url:encode(Signer),
    <<UnsignedToken/binary, ".", Signed/binary>>.


%%% Verify %%%
verify(JWT, Key) ->
    verify(JWT, Key, <<"HS256">>).

verify(JWT, Key, Algorithm) ->
    [Header_segment, Data] = binary:split(JWT, <<".">>),
    [Payload_segment, Crypto_segment] = binary:split(Data, <<".">>),
    Payload = jsx:decode(base64url:decode(Payload_segment)),
    Header = jsx:decode(base64url:decode(Header_segment)),
    Signature = base64url:decode(Crypto_segment),
    Signing_input = <<Header_segment/binary, ".", Payload_segment/binary>>,
    verify(Algorithm, Key, Signing_input, Header, Signature, Payload).

verify(_Algorithm, _Key = undefined, _Signing_input, _Header, _Signature, Payload) ->
    Payload;
verify(Algorithm, Key, Signing_input, Header, Signature, Payload) ->
    HeaderAlg = proplists:get_value(<<"alg">>, Header),
    Verified = verifier(get_signature_type(Algorithm), Key, Signing_input, Signature),
    verify([Verified, HeaderAlg == Algorithm, Payload]).

verify([true = _Verified, true = _AlgoMatch, Payload]) ->
    Payload;
verify([false, _, _Payload]) ->
    {error, "Bad key or secret"};
verify([_Verified, false, _Payload]) ->
    {error, "Algorithm mismatch"}.

%%====================================================================
%% Internal functions
%%====================================================================
signer({hmac, Algorithm}, Secret, UnsignedToken) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:hmac(Digest, Secret, UnsignedToken);

signer({rsa, Algorithm}, PrivateKeyPem, UnsignedToken) when is_binary(PrivateKeyPem) ->
    [RSAEntry] = public_key:pem_decode(PrivateKeyPem),
    Key = public_key:pem_entry_decode(RSAEntry),
    E = Key#'RSAPrivateKey'.publicExponent,
    N = Key#'RSAPrivateKey'.modulus,
    D = Key#'RSAPrivateKey'.privateExponent,
    signer({rsa, Algorithm}, [E, N, D], UnsignedToken);
signer({rsa, Algorithm}, [E, N, D], UnsignedToken) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:sign(rsa, Digest, UnsignedToken, [E,N,D]);

%% EC
signer({ec, _Algorithm}, ECPrivateKeyPem, UnsignedToken) when is_binary(ECPrivateKeyPem) ->
    [{'EcpkParameters', _, not_encrypted} = _Entry1,
      {'ECPrivateKey', _, not_encrypted} = Entry2] = public_key:pem_decode(ECPrivateKeyPem),
    ECPrivateKey = public_key:pem_entry_decode(Entry2),
    Signature = public_key:sign(UnsignedToken, sha512, ECPrivateKey),
    Signature.
%% HMAC
verifier({hmac, Algorithm}, Secret, Signing_input, Signature) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:hmac(Digest, Secret, Signing_input) == Signature;
%% RSA
verifier({rsa, Algorithm}, PublicKeyPem, Signing_input, Signature) when is_binary(PublicKeyPem) ->
    [RSAEntry] = public_key:pem_decode(PublicKeyPem),
    Key = public_key:pem_entry_decode(RSAEntry),
    E = Key#'RSAPublicKey'.publicExponent,
    N = Key#'RSAPublicKey'.modulus,
    verifier({rsa, Algorithm}, [E, N], Signing_input, Signature);
verifier({rsa, Algorithm}, [E, N], Signing_input, Signature) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:verify(rsa, Digest, Signing_input, Signature, [E, N]);
%% EC
verifier({ec, Algorithm}, ECPublicKeyPem, Signing_input, Signature) when is_binary(ECPublicKeyPem) ->
    io:format("Algorithm ~p",[Algorithm]),
    [{'SubjectPublicKeyInfo', _, _} = PubEntry0] = public_key:pem_decode(ECPublicKeyPem),
    ECPublicKey = public_key:pem_entry_decode(PubEntry0),
    Digest = get_hash_algorithm(Algorithm),
    public_key:verify(Signing_input, Digest, Signature, ECPublicKey).


get_hash_algorithm(Bin) ->
    {_Title,_AlgorithmBin,HashAlgorithm,_SignatureType} = lists:keyfind(Bin, 2, ?ALGO),
    HashAlgorithm.  

get_signature_type(Bin) ->
    get_signature_type(lists:keyfind(Bin, 2, ?ALGO), Bin).
get_signature_type({_Title,AlgorithmBin,_HashAlgorithm,SignatureType}, _Bin) ->
    {SignatureType, AlgorithmBin};
get_signature_type(false, Bin) ->
    erlang:error({badarg, Bin}).


