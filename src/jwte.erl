%% Copyright (c) 2016, Thomas Bhatia <thomas.bhatia@eo.io>.
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions are
%% met:
%%
%% * Redistributions of source code must retain the above copyright
%%   notice, this list of conditions and the following disclaimer.
%%
%% * Redistributions in binary form must reproduce the above copyright
%%   notice, this list of conditions and the following disclaimer in the
%%   documentation and/or other materials provided with the distribution.
%%
%% * The names of its contributors may not be used to endorse or promote
%%   products derived from this software without specific prior written
%%   permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%% A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%% OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
%% LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
%% OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


-module(jwte).

-include_lib("public_key/include/public_key.hrl").

%% API exports
-export([peek/1]).

-export([sign/1, sign/2, sign/3]).

-export([verify/1, verify/2, verify/3]).

-export([check_registered_claims/1]).

-type key() :: binary() | list().
-type alg() :: binary() | list().

-type jwt() :: binary().

-export_type([key/0, alg/0]).

-define(ALGO,
        [{hs256, <<"HS256">>, sha256, hmac},
         {hs384, <<"HS384">>, sha384, hmac},
         {hs512, <<"HS512">>, sha512, hmac},
         {rs256, <<"RS256">>, sha256, rsa},
         {rs384, <<"RS384">>, sha384, rsa},
         {rs512, <<"RS512">>, sha512, rsa},
         {ec256, <<"EC256">>, sha256, ec},
         {ec384, <<"EC384">>, sha384, ec},
         {ec512, <<"EC512">>, sha512, ec}
         ]).

%%====================================================================
%% API functions
%%====================================================================

%%====================================================================
%% @doc Peek claims. Return claims without verifying signature.
%% @end
%%====================================================================
-spec peek(binary()) -> {ok, map()}.
peek(JWT) ->
    Unpacked = unpacker(JWT),
    {ok, Payload} = maps:get(payload, Unpacked),
    {ok, maps:from_list(Payload)}.

%%====================================================================
%% @doc Sign claims. If no algorithm is specified we use HS256.
%% @end
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
%% @end
%%====================================================================
verify(JWT, Key) ->
    verify(JWT, Key, <<"HS256">>).

verify(JWT, Key, Algorithm) when is_binary(Algorithm) ->
    {Type, SigAlgo} = get_signature_type(Algorithm),
    verify(JWT, Key, {Type, SigAlgo});

verify(_JWT, _Key, {error, Error}) ->
    {error, Error};

verify(JWT, Key, {Type, SigAlgo}) ->
    UnpackedJWT = unpacker(JWT),

    {ok,  #{<<"alg">> := Alg, <<"typ">> := <<"JWT">>}} = maps:get(header, UnpackedJWT),
    {ok, Payload} = maps:get(payload, UnpackedJWT),
    {ok, Signature} = maps:get(signature, UnpackedJWT),
    {ok, SigningInput} = maps:get(signing_input, UnpackedJWT),

    VerifyKeyStatus = verify_key(#{sig => {Type, SigAlgo},
                             key => Key,
                             signing_input => SigningInput,
                             signature => Signature}),

    VerifyClaimsStatus = check_registered_claims(Payload),

    verify(#{alg => Alg,
             key_verified => VerifyKeyStatus,
             sig_algo => SigAlgo,
             payload => Payload,
             claims_verified => VerifyClaimsStatus}).

verify(#{alg := Alg,
         key_verified := true,
         sig_algo := SigAlgo,
         payload := Payload,
         claims_verified := true}) when Alg == SigAlgo ->
    {ok, maps:from_list(Payload)};
verify(#{key_verified := false}) ->
    {error, "Bad key or secret"};
verify(#{alg := false}) ->
    {error, "Algorithm mismatch"};
verify(#{claims_verified := false}) ->
    {error, "Invalid claims"}.

%%====================================================================
%% Internal functions
%%====================================================================
%%====================================================================
%% @doc Unpacker
%% @end
%%====================================================================
-spec unpacker(jwt()) -> map() | {error, term()}.
unpacker(JWT) ->
    [RawHeader, RawPayload, RawSignature] = binary:split(JWT, <<".">>, [global]),
    Data = #{header => [],
            payload => [],
            signature => [],
            raw_header => RawHeader,
            raw_payload => RawPayload,
            raw_signature => RawSignature},
    do_unpacking(Data).

do_unpacking(#{raw_header := RawHeader,
           header := []} = Data) ->
    do_unpacking(Data#{header => decode_header(RawHeader)});
do_unpacking(#{header := {ok, _Header},
           raw_payload := RawPayload,
           payload := []} = Data) ->
    do_unpacking(Data#{payload => decode_payload(RawPayload)});
do_unpacking(#{payload := {ok, _Payload},
           raw_signature := RawSignature,
           signature := []} = Data) ->
    do_unpacking(Data#{signature => get_signature(RawSignature)});
do_unpacking(#{payload := {ok, _Payload},
           header := {ok, _Header},
           signature := {ok, _Signature},
           raw_header := RawHeader,
           raw_payload := RawPayload} = Data) ->
    Data#{signing_input => get_signing_input(RawHeader, RawPayload)};
do_unpacking(_) ->
    throw({error, invalid_jwt}).

decode_header(RawHeader) when is_binary(RawHeader) ->
    decode_header(#{b64 => decode_base64(RawHeader)});
decode_header(#{b64 := {ok, B64Bin}}) ->
    decode_header(#{json => decode_json(B64Bin)});
decode_header(#{json := {ok, DecodedHeaderMap}}) ->
    {ok, DecodedHeaderMap};
decode_header(#{b64 := {error, Error}}) ->
    {error, {decode_header, [Error]}};
decode_header(#{json := {error, Error}}) ->
    {error, {decode_header, [Error]}}.

decode_payload(RawPayload) when is_binary(RawPayload) ->
    decode_payload(#{b64 => decode_base64(RawPayload)});
decode_payload(#{b64 := {ok, B64Bin}}) ->
    decode_payload(#{json => decode_json(B64Bin, [])});
decode_payload(#{json := {ok, DecodedPayloadMap}}) ->
    {ok, DecodedPayloadMap};
decode_payload(#{b64 := {error, Error}}) ->
    {error, {decode_payload, [Error]}};
decode_payload(#{json := {error, Error}}) ->
    {error, {decode_payload, [Error]}}.

-spec get_signature(binary()) -> {ok, list()}.
get_signature(RawSignature) ->
    Signature = base64url:decode(RawSignature),
    {ok, Signature}.

get_signing_input(Header_segment, Payload_segment) ->
    Signing_input = <<Header_segment/binary, ".", Payload_segment/binary>>,
    {ok, Signing_input}.


%%====================================================================
%% @doc Signer
%% %% @end
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
    crypto:sign(rsa, Digest, UnsignedToken, [E, N, D]);
signer({ec, _Algorithm}, ECPrivateKeyPem, UnsignedToken) when is_binary(ECPrivateKeyPem) ->
    [{'EcpkParameters', _, not_encrypted},
      {'ECPrivateKey', _, not_encrypted} = Entry2] = public_key:pem_decode(ECPrivateKeyPem),
    ECPrivateKey = public_key:pem_entry_decode(Entry2),
    public_key:sign(UnsignedToken, sha512, ECPrivateKey);

signer({error, Error}, _, _) ->
    {error, Error}.

%%====================================================================
%% @doc Verify Key
%% @end
%%====================================================================
verify_key(#{sig := {hmac, Algorithm},
             key := Key,
             signing_input := Signing_input,
             signature := Signature}) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:hmac(Digest, Key, Signing_input) == Signature;
verify_key(#{sig := {rsa, _Algorithm},
             key := PublicKeyPem} = P) when is_binary(PublicKeyPem) ->
    [RSAEntry] = public_key:pem_decode(PublicKeyPem),
    Key = public_key:pem_entry_decode(RSAEntry),
    E = Key#'RSAPublicKey'.publicExponent,
    N = Key#'RSAPublicKey'.modulus,
    NP = P#{key := [E, N]},
    verify_key(NP);
%%% @doc Key is decoded PEM.
verify_key(#{sig := {rsa, Algorithm},
             key := [E, N],
             signing_input := Signing_input,
             signature := Signature}) ->
    Digest = get_hash_algorithm(Algorithm),
    crypto:verify(rsa, Digest, Signing_input, Signature, [E, N]);
verify_key(#{sig := {ec, Algorithm},
             key := ECPublicKeyPem,
             signing_input := Signing_input,
             signature := Signature}) when is_binary(ECPublicKeyPem) ->
    [{'SubjectPublicKeyInfo', _, _} = PubEntry0] = public_key:pem_decode(ECPublicKeyPem),
    ECPublicKey = public_key:pem_entry_decode(PubEntry0),
    Digest = get_hash_algorithm(Algorithm),
    public_key:verify(Signing_input, Digest, Signature, ECPublicKey).

%%====================================================================
%% @doc Verify registered claims
%% Reference: https://www.iana.org/assignments/jwt/jwt.xhtml
%% RFC 7519 Section 4.1.1 - 4.1.7:
%% iss, sub, aud, exp, nbf, iat, jti
%%====================================================================

get_registered_claims_set() ->
    {ok, EnabledClaims} = application:get_env(jwte, claims),
    EnabledClaims.

get_a_claim_set(Claim) ->
    {ok, Options} = application:get_env(jwte, claims_opt),
    lists:keyfind(Claim, 1, Options).

%% @doc check for duplicate claims
check_registered_claims(Claims) ->
    ContainsDuplicates = length(proplists:get_keys(Claims)) /= length(Claims),
    case ContainsDuplicates of
        true ->
            {error, found_duplicate_claims};
        false ->
            ClaimsSet = get_registered_claims_set(),
            VerifiedList = do_verify_claims(ClaimsSet, Claims, []),
            lists:all(fun({_K, Value}) ->
                Value == true
            end, VerifiedList)
    end.

do_verify_claims([], _Claims, Acc) ->
    Acc;
do_verify_claims([{_K, false} | ClaimsSet], Claims, Acc) ->
    do_verify_claims(ClaimsSet, Claims, Acc);
do_verify_claims([ClaimSet | ClaimsSet], Claims, Acc) ->
    Status = verify_claim(ClaimSet, Claims),
    do_verify_claims(ClaimsSet, Claims, [{ClaimSet, Status} | Acc]).

verify_claim({K, _V} = ClaimSet, Claims) ->
    case lists:keyfind(K, 1, Claims) of
        false ->
            false;
        {_, Claim} ->
            do_verify_claim(ClaimSet, Claim)
    end.

do_verify_claim({_, false}, _Claim) ->
    true;
do_verify_claim({<<"iss">>, ClaimSet}, Claim) ->
    ClaimSet == Claim;
do_verify_claim({<<"sub">>, ClaimSet}, Claim) ->
    ClaimSet == Claim;
do_verify_claim({<<"aud">>, ClaimSet}, Claim) ->
    ClaimSet == Claim;
do_verify_claim({<<"exp">>, true}, Claim) ->
    DriftEnv = get_a_claim_set(<<"allowed_drift">>),
    Drift = if DriftEnv == false -> 0; true -> {_, DSet} = DriftEnv, DSet end,
    io:format(user, "Claim ~p~n Drift ~p~n", [Claim, Drift]),
    epoch() - (Claim + Drift) < 0;
do_verify_claim({<<"nbf">>, true}, Claim) ->
    Claim - epoch() >= 0;
do_verify_claim({<<"iat">>, true}, Claim) ->
    Claim;
do_verify_claim({<<"jti">>, ClaimSet}, Claim) ->
    ClaimSet == Claim.

%%====================================================================
%% @doc Helpers
%% @end
%%====================================================================
get_hash_algorithm(Bin) ->
    {_Title, _AlgorithmBin, HashAlgorithm, _SignatureType} = lists:keyfind(Bin, 2, ?ALGO),
    HashAlgorithm.

get_signature_type(Bin) ->
    get_signature_type(lists:keyfind(Bin, 2, ?ALGO), Bin).
get_signature_type({_Title, AlgorithmBin, _HashAlgorithm, SignatureType}, _Bin) ->
    {SignatureType, AlgorithmBin};
get_signature_type(false, _Bin) ->
    throw({error, unsupported_algorithm}).

epoch() ->
    os:system_time(seconds).

decode_base64(B64Bin) ->
    try base64url:decode(B64Bin) of
        DecodedB64 when is_binary(DecodedB64) ->
            {ok, DecodedB64}
    catch
        _Exc:_Type ->
            throw({error, decoding_B64})
    end.

decode_json(JSONBin) ->
    decode_json(JSONBin, [return_maps]).

decode_json(JSONBin, Opts) ->
    try jsx:decode(JSONBin, Opts) of
        DecodedJSON ->
            {ok, DecodedJSON}
    catch
        _Exc:_Type ->
            throw({error, decoding_JSON})
    end.
