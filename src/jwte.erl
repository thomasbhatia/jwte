% TODO:
% Supports HMAC, RSA, EC. TODO: Pass atom instead of Binary Algorithm.
%% use verify_strict?
%% Typespec
% Add cuttlefish config

-module(jwte).

-include("jwte.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API exports
-export([peek/1, sign/1, sign/2, sign/3, verify/1, verify/2, verify/3]).

-export([check_claims/1, check_claims/2]).

-type key() :: binary() | list().
-type alg() :: binary() | list().

-type jwt() :: binary().

-export_type([key/0, alg/0]).


%%====================================================================
%% API functions
%%====================================================================

%%====================================================================
%% @doc Peek claims. Return claims without verifying signature.
%%====================================================================
-type peek() :: map().
-spec peek(jwt()) -> {ok, peek()}.
peek(JWT) ->
    Unpacked = unpacker(JWT),
    % {ok, Header} = maps:get(header, Unpacked),
    {ok, Payload} = maps:get(payload, Unpacked),
    % Signature = maps:get(signature, Unpacked),
    % _SigningInput = maps:get(signing_input, Unpacked),
    % {ok, #{header => Header, payload => Payload, signature => Signature}}.
    {ok, Payload}.

%%====================================================================
%% @doc Sign claims. If no algorithm is specified we use HS256.
%%====================================================================
sign(Claims, Key) ->
    sign(#{claims => Claims, key => Key, alg => <<"HS256">>}).

sign(Claims, Key, Alg) ->
    sign(#{claims => Claims, key => Key, alg => Alg}).

sign(#{claims := Claims, key := Key, alg := Alg}) when is_binary(Alg) ->
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

%%====================================================================
%% @doc Verify key and claims
%%====================================================================
verify(JWT, Key) ->
    verify(JWT, Key, <<"HS256">>).

verify(JWT, Key, Algorithm) ->
    Unpacked = unpacker(JWT),
    {ok,  #{<<"alg">> := Alg, <<"typ">> := <<"JWT">>}} = maps:get(header, Unpacked),
    {ok, Payload} = maps:get(payload, Unpacked),
    Signature = maps:get(signature, Unpacked),
    SigningInput = maps:get(signing_input, Unpacked),
    Type = get_signature_type(Algorithm),
    VerifyKey = verify_key(#{sig => Type, key => Key, signing_input => SigningInput, signature => Signature}),
    verify(#{alg => Alg, key_verified => VerifyKey, sig => Type, payload => Payload}).

verify(#{alg := Alg, key_verified := true, sig := {_Type, Sig_Alg}, payload := Payload}) when Alg == Sig_Alg ->
    {ok, Payload};
verify(#{key_verified := false}) ->
    {error, "Bad key or secret"};
verify(#{alg := false}) ->
    {error, "Algorithm mismatch"}.

%%====================================================================
%% Internal functions
%%====================================================================
%%====================================================================
%% Unpacker
%%====================================================================
-spec unpacker(jwt()) -> {ok, map()} | {error, term()}.
unpacker(JWT) when is_binary(JWT) ->
    [RawHeader, RawPayload, RawSignature] = binary:split(JWT, <<".">>, [global]),
    unpacker(#{raw_header => RawHeader, raw_payload => RawPayload, raw_signature => RawSignature, header => [], payload => [], signature => []});
unpacker(#{raw_header := RawHeader, header := []} = Data) ->
    unpacker(Data#{header => decode_header(RawHeader)});
unpacker(#{header := {ok, _Header}, raw_payload := RawPayload, payload := []} = Data) ->
    unpacker(Data#{payload => decode_payload(RawPayload)});
unpacker(#{payload := {ok, _Payload}, raw_signature := RawSignature, signature := []} = Data) ->
    unpacker(Data#{signature => get_signature(RawSignature)});
unpacker(#{payload := {ok, _Payload}, header := {ok, _Header}, signature := {ok, Signature}, raw_header := RawHeader, raw_payload := RawPayload} = Data) ->
    {ok, SigningInputBin} = get_signing_input(RawHeader, RawPayload),
    Data#{signing_input => SigningInputBin, signature => Signature};
unpacker(_) ->
    {error, error}.

decode_header(RawHeader) when is_binary(RawHeader) ->
    decode_header(#{b64 => decode_base64(RawHeader)});
decode_header(#{b64 := {ok, B64Bin}}) ->
    decode_header(#{json => decode_JSON(B64Bin)});
decode_header(#{json := {ok, DecodedHeaderMap}}) ->
    {ok, DecodedHeaderMap};
decode_header(#{b64 := {error, Error}}) ->
    {error, {decode_header, [Error]}};
decode_header(#{json := {error, Error}}) ->
    {error, {decode_header, [Error]}}.

decode_payload(RawPayload) when is_binary(RawPayload) ->
    decode_payload(#{b64 => decode_base64(RawPayload)});
decode_payload(#{b64 := {ok, B64Bin}}) ->
    decode_payload(#{json => decode_JSON(B64Bin)});
decode_payload(#{json := {ok, DecodedPayloadMap}}) ->
    {ok, DecodedPayloadMap};
decode_payload(#{b64 := {error, Error}}) ->
    {error, {decode_payload, [Error]}};
decode_payload(#{json := {error, Error}}) ->
    {error, {decode_payload, [Error]}}.

get_signature(RawSignature) ->
    Signature = base64url:decode(RawSignature),
    {ok, Signature}.
get_signing_input(Header_segment, Payload_segment) ->
    Signing_input = <<Header_segment/binary, ".", Payload_segment/binary>>,
    {ok, Signing_input}.


%%====================================================================
%% Signer
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
signer({ec, _Algorithm}, ECPrivateKeyPem, UnsignedToken) when is_binary(ECPrivateKeyPem) ->
    [{'EcpkParameters', _, not_encrypted} = _Entry1,
      {'ECPrivateKey', _, not_encrypted} = Entry2] = public_key:pem_decode(ECPrivateKeyPem),
    ECPrivateKey = public_key:pem_entry_decode(Entry2),
    public_key:sign(UnsignedToken, sha512, ECPrivateKey).


%%====================================================================
%% Verify Key
%%====================================================================
verify_key(#{sig := {hmac, Algorithm}, key := Key, signing_input := Signing_input, signature := Signature}) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:hmac(Digest, Key, Signing_input) == Signature;
verify_key(#{sig := {rsa, _Algorithm}, key := PublicKeyPem} = P) when is_binary(PublicKeyPem) ->
    [RSAEntry] = public_key:pem_decode(PublicKeyPem),
    Key = public_key:pem_entry_decode(RSAEntry),
    E = Key#'RSAPublicKey'.publicExponent,
    N = Key#'RSAPublicKey'.modulus,
    NP = P#{key := [E,N]},
    verify_key(NP);
%%% @doc Key is decoded PEM.
verify_key(#{sig := {rsa, Algorithm}, key := [E, N], signing_input := Signing_input, signature := Signature}) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:verify(rsa, Digest, Signing_input, Signature, [E, N]);
verify_key(#{sig := {ec, Algorithm}, key := ECPublicKeyPem, signing_input := Signing_input, signature := Signature}) when is_binary(ECPublicKeyPem) ->
    [{'SubjectPublicKeyInfo', _, _} = PubEntry0] = public_key:pem_decode(ECPublicKeyPem),
    ECPublicKey = public_key:pem_entry_decode(PubEntry0),
    Digest = get_hash_algorithm(Algorithm),
    public_key:verify(Signing_input, Digest, Signature, ECPublicKey).

%%====================================================================
%% Verify Registered Claims
%%====================================================================
% %% iss; sub; aud; exp; nbf; iat; jti;
get_claims_set() ->
    {ok, ISS} = application:get_env(jwte, iss),
    {ok, SUB} = application:get_env(jwte, sub),
    {ok, AUD} = application:get_env(jwte, aud),
    {ok, EXP} = application:get_env(jwte, allowed_drift),
    {ok, NBF} = application:get_env(jwte, nbf),
    {ok, IAT} = application:get_env(jwte, iat),
    {ok, JTI} = application:get_env(jwte, jti),
    #{iss => ISS, sub => SUB, aud => AUD, exp => EXP + epoch(), nbf => NBF, iat => IAT, jti => JTI}.

check_claims(Claims) ->
    check_claims(Claims, get_claims_set()).

check_claims(#{iss := ISS} = Claims, #{iss := ISSSET} = ClaimsSet) when ISS =:= ISSSET ->
    check_claims(Claims, maps:remove(iss, ClaimsSet));
check_claims(#{sub := Sub} = Claims, #{sub := SubSET} = ClaimsSet) when Sub =:= SubSET ->
    check_claims(Claims, maps:remove(sub, ClaimsSet));
check_claims(#{aud := AUD} = Claims, #{aud := AUDSET} = ClaimsSet) when AUD =:= AUDSET ->
    check_claims(Claims, maps:remove(aud, ClaimsSet));
check_claims(#{exp := EXP} = Claims, #{exp := EXPSET} = ClaimsSet) when EXP =< EXPSET ->
    check_claims(Claims, maps:remove(exp, ClaimsSet));
check_claims(#{nbf := NBF} = Claims, #{nbf := NBFSET} = ClaimsSet) when NBF > NBFSET ->
    check_claims(Claims, maps:remove(nbf, ClaimsSet));
check_claims(#{iat := IAT} = Claims, #{iat := IATSET} = ClaimsSet) when IAT =:= IATSET ->
    check_claims(Claims, maps:remove(iat, ClaimsSet));
check_claims(#{jti := JTI} = Claims, #{jti := JTISET} = ClaimsSet) when JTI =:= JTISET ->
    check_claims(Claims, maps:remove(jti, ClaimsSet));
check_claims(Claims, ClaimsSet) when map_size(ClaimsSet) == 0 ->
    {ok, Claims};
check_claims(Claims, ClaimsSet) ->
    {error, {Claims, ClaimsSet}}.


%%====================================================================
%% Helpers
%%====================================================================
get_hash_algorithm(Bin) ->
    {_Title,_AlgorithmBin,HashAlgorithm,_SignatureType} = lists:keyfind(Bin, 2, ?ALGO),
    HashAlgorithm.

get_signature_type(Bin) ->
    get_signature_type(lists:keyfind(Bin, 2, ?ALGO), Bin).
get_signature_type({_Title,AlgorithmBin,_HashAlgorithm,SignatureType}, _Bin) ->
    {SignatureType, AlgorithmBin};
get_signature_type(false, Bin) ->
    erlang:error({badarg, Bin}).

epoch() ->
    erlang:system_time(seconds).

decode_base64(B64Bin) ->
    try base64url:decode(B64Bin) of
        DecodedB64 when is_binary(DecodedB64) ->
            {ok, DecodedB64}
    catch
        _Exc:_Type ->
            throw({error, decoding_B64})
    end.

decode_JSON(JSONBin) ->
    try jsx:decode(JSONBin, [return_maps]) of
        DecodedJSON ->
            {ok, DecodedJSON}
    catch
        _Exc:_Type ->
            throw({error, decoding_JSON})
    end.










