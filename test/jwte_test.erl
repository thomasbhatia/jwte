-module(jwte_test).

-include("jwte.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

jwte_test_() ->
    {setup,
    fun setup/0,
    fun cleanup/1,
    [jwte_tests_()]
    }.

setup() ->
    Claims = [{iss, <<"MyAPP">>},
           {sub, <<"AppAuth">>},
           {aud, <<"InternalDivision">>},
           {exp, true},
           {allowed_drift, 1000},
           {nbf, true},
           {iat, true},
           {jti, true}],
    application:set_env(jwte, claims, Claims).

cleanup(_Pid) ->
    application:set_env(jwte, claims, []).

jwte_tests_() ->
        [{"Peek at Claims", fun check_peek/0},
         {"Verify HMAC", fun verify_hmac/0},
         {"Verify HMAC without key", fun no_key_verify_hmac/0},
         {"Verify HMAC invalid key or algorithm", fun invalid_verify_hmac/0},
         {"Verify RSA", fun verify_rsa/0},
         {"Verify RSA with invalid key or algorithm", fun invalid_verify_rsa/0},
         {"Sign HMAC", fun sign_hmac/0},
         {"Sign HMAC with invalid key or algorithm", fun invalid_sign_hmac/0},
         {"Sign RSA", fun sign_rsa/0},
         {"Sign RSA with invalid key or algorithm", fun invalid_sign_rsa/0},
         {"Sign and Verify EC", fun sign_verify_ec/0},
         {"verify ISS claim", fun verify_claim_iss/0},
         {"Verify EXP claim", fun verify_claim_exp/0},
         {"verify SUB claim", fun verify_claim_sub/0},
         {"verify NBF claim", fun verify_claim_nbf/0},
         {"verify AUD claim", fun verify_claim_aud/0},
         {"verify IAT claim", fun verify_claim_iat/0},
         {"verify JTI claim", fun verify_claim_jti/0}
        ].

rsa_pri_pem() ->
    {ok, RSAPriPem} = file:read_file("test/data/rsakey_2048.pem"),
    RSAPriPem.

rsa_pub_pem() ->
    {ok, RSAPubKeyPem} = file:read_file("test/data/rsakey_2048_pub.pem"),
    RSAPubKeyPem.

ec_pri_pem() ->
    {ok, RSAPriPem} = file:read_file("test/data/ec_sect571r1_prikey.pem"),
    RSAPriPem.

ec_pub_pem() ->
    {ok, RSAPubKeyPem} = file:read_file("test/data/ec_sect571r1_pubkey.pem"),
    RSAPubKeyPem.

invalid_rsa_pub_pem() ->
    {ok, BadRSAPubKeyPem} = file:read_file("test/data/bad_rsakey_2048_pub.pem"),
    BadRSAPubKeyPem.

get_rsa_pubkey_decoded(RSAPubKeyPem) ->
    [RSAEntry] = public_key:pem_decode(RSAPubKeyPem),
    Key = public_key:pem_entry_decode(RSAEntry),
    E = Key#'RSAPublicKey'.publicExponent,
    N = Key#'RSAPublicKey'.modulus,
    [E, N].

get_rsa_prikey_decoded(RSAPriKeyPem) ->
    [RSAEntry] = public_key:pem_decode(RSAPriKeyPem),
    Key = public_key:pem_entry_decode(RSAEntry),
    E = Key#'RSAPrivateKey'.publicExponent,
    N = Key#'RSAPrivateKey'.modulus,
    D = Key#'RSAPrivateKey'.privateExponent,
    [E, N, D].

secret() ->
    "secret".

bad_secret() ->
    "badsecret".

claims() ->
    [{<<"sub">>, <<"1234567890">>},
    {<<"name">>, <<"John Doe">>},
    {<<"admin">>, true}].

claims_map() ->
    #{<<"sub">> => <<"1234567890">>,
      <<"name">> => <<"John Doe">> ,
      <<"admin">> => true}.

set_env() ->
    application:set_env(jwte, <<"iss">>, <<"MyAPP">>),
    application:set_env(jwte, <<"sub">>, <<"AppAuth">>),
    application:set_env(jwte, <<"aud">>, <<"InternalDivision">>),
    application:set_env(jwte, <<"exp">>, true),
    application:set_env(jwte, <<"nbf">>, true),
    application:set_env(jwte, <<"iat">>, true),
    application:set_env(jwte, <<"jti">>, true).

%% Tests
check_peek() ->
    ?assertEqual({ok, claims_map()}, jwte:peek(jwt(hs256))).

verify_hmac() ->
    application:set_env(jwte, claims, []),
    [?assertEqual({ok, claims_map()}, verify_valid_hmac({Type, Bin})) || {Type, Bin} <- grp_HMAC()],
    ?assertEqual({ok, claims_map()}, verify_valid_hmac_256_default()).

no_key_verify_hmac() ->
    ?assertException(error, function_clause, jwte:verify(jwt(hs256))).

invalid_verify_hmac() ->
    ?assertEqual({error,"Bad key or secret"}, verify_invalid_hmac_secret()),
    ?assertError({badarg,_}, verify_invalid_hmac()).

sign_hmac() ->
    [?assertEqual(jwt(Type), sign_valid_hmac(Bin)) || {Type, Bin} <- grp_HMAC()],
    ?assertEqual(jwt(hs256), sign_valid_hmac_256_default()).

invalid_sign_hmac() ->
    ?assertError({badarg,_}, sign_invalid_hmac()).

verify_rsa() ->
    [?assertEqual({ok, claims_map()}, verify_valid_rsa({Type, Bin})) || {Type, Bin} <- grp_RSA()],
    ?assertEqual({ok, claims_map()}, verify_valid_rsa_e_n(rs256)).

invalid_verify_rsa() ->
    ?assertEqual({error,"Bad key or secret"}, verify_invalid_rsa_pub_pem()),
    ?assertError({badarg,_}, verify_invalid_rsa_algo()).

sign_rsa() ->
    [?assertEqual(jwt(Type), sign_valid_rsa(Bin)) || {Type, Bin} <- grp_RSA()],
    ?assertEqual(jwt(rs256), sign_valid_rsa_e_n_d(rs256)).

invalid_sign_rsa() ->
    ?assertError({badarg,_}, sign_invalid_rsa_algo()).

sign_verify_ec() ->
    Signed = sign_ec(ec512),
    ?assertEqual({ok, claims_map()}, verify_ec({Signed, <<"EC512">>})).


%iss: The issuer of the token
verify_claim_iss() ->
    application:set_env(jwte, claims, [claimset_iss()]),
    ?assertEqual(true, jwte:check_registered_claims(valid_iss())),
    ?assertEqual(false, jwte:check_registered_claims(invalid_iss())).

valid_iss() ->
    [{<<"iss">>, <<"MyAPP">>}].

invalid_iss() ->
    [{<<"iss">>, <<"APP">>}].

claimset_iss() ->
    {<<"iss">>, <<"MyAPP">>}.

%exp: This will define the expiration in NumericDate value. The expiration MUST be after the current date/time.
verify_claim_exp() ->
    application:set_env(jwte, claims, [claimset_exp()]),
    application:set_env(jwte, claims_opt, [{<<"allowed_drift">>, drift()}]),
    ?assertEqual(true, jwte:check_registered_claims(valid_exp())),
    ?assertEqual(false, jwte:check_registered_claims(expired_exp())).

claimset_exp() ->
    {<<"exp">>, true}.

valid_exp() ->
    [{<<"exp">>, epoch()}].

expired_exp() ->
    [{<<"exp">>, epoch() - drift() - 1}].

drift() ->
    1000.

epoch() -> os:system_time(seconds).

%sub: The subject of the token
verify_claim_sub() ->
    application:set_env(jwte, claims, [claimset_sub()]),
    ?assertEqual(true, jwte:check_registered_claims(valid_sub_claim())),
    ?assertEqual(false, jwte:check_registered_claims(invalid_sub_claim())).

claimset_sub() ->
    {<<"sub">>, <<"https://github.com/thomasbhatia/jwte">>}.

invalid_sub_claim() ->
    [{<<"sub">>, <<"https://github.com/thomasbhatia/jwtefoo">>}].

valid_sub_claim() ->
    [claimset_sub()].

%aud: The audience of the token
verify_claim_aud() ->
    application:set_env(jwte, claims, [claimset_aud()]),
    ?assertEqual(true, jwte:check_registered_claims(valid_aud())),
    ?assertEqual(false, jwte:check_registered_claims(invalid_aud())).

claimset_aud() ->
    {<<"aud">>, <<"https://github.com/thomasbhatia/jwte">>}.

valid_aud() ->
    [claimset_aud()].

invalid_aud() ->
    [{<<"aud">>, <<"https://github.com/thomasbhatia/doraki">>}].

%nbf: Defines the time before which the JWT MUST NOT be accepted for processing
verify_claim_nbf() ->
    application:set_env(jwte, claims, [claimset_nbf()]),
    ?assertEqual(true, jwte:check_registered_claims(valid_nbf())),
    ?assertEqual(false, jwte:check_registered_claims(pre_validity_nbf())).

claimset_nbf() ->
    {<<"nbf">>, true}.

valid_nbf() ->
    [{<<"nbf">>, epoch()}].

pre_validity_nbf() ->
    [{<<"nbf">>, 1496074471}].

%iat: The time the JWT was issued. Can be used to determine the age of the JWT
verify_claim_iat() ->
    application:set_env(jwte, claims, [claimset_iat()]),
    ?assertEqual(true, jwte:check_registered_claims(valid_iat())).

claimset_iat() ->
    {<<"iat">>, true}.

valid_iat() ->
    [claimset_iat()].

%jti: Unique identifier for the JWT. Can be used to prevent the JWT from being replayed. This is helpful for a one time use token.
verify_claim_jti() ->
    application:set_env(jwte, claims, [claimset_jti()]),
    ?assertEqual(true, jwte:check_registered_claims(valid_jti())).

claimset_jti() ->
    {<<"jti">>, <<"spacegoesdowndown">>}.

valid_jti() ->
    [claimset_jti()].

%% End tests

%% Verify HMAC
verify_valid_hmac_256_default() ->
    jwte:verify(jwt(hs256), secret()).

verify_valid_hmac({Type, Bin}) ->
    jwte:verify(jwt(Type), secret(), Bin).

verify_invalid_hmac_secret() ->
    jwte:verify(jwt(hs256), bad_secret()).

verify_invalid_hmac() ->
    jwte:verify(jwt(hs256), secret(), <<"HS111">>).

%% Sign HMAC
sign_valid_hmac_256_default() ->
    jwte:sign(claims(), secret()).

sign_valid_hmac(Bin) ->
    jwte:sign(claims(), secret(), Bin).

sign_invalid_hmac() ->
    jwte:sign(jwt(hs256), secret(), <<"HS111">>).

%% Verify RSA
verify_valid_rsa({Type, Bin}) ->
    jwte:verify(jwt(Type), rsa_pub_pem(), Bin).

verify_valid_rsa_e_n(rs256) ->
    jwte:verify(jwt(rs256), get_rsa_pubkey_decoded(rsa_pub_pem()), <<"RS256">>).

verify_invalid_rsa_pub_pem() ->
    jwte:verify(jwt(hs256), invalid_rsa_pub_pem()).

verify_invalid_rsa_algo() ->
    jwte:verify(jwt(hs256), rsa_pub_pem(), <<"RS111">>).

%% Sign RSA
sign_valid_rsa(BIN) ->
    jwte:sign(claims(), rsa_pri_pem(), BIN).

sign_valid_rsa_e_n_d(rs256) ->
    jwte:sign(claims(), get_rsa_prikey_decoded(rsa_pri_pem()), <<"RS256">>).

sign_invalid_rsa_algo() ->
    jwte:sign(claims(), rsa_pri_pem(), <<"RS111">>).

%% Verify EC
verify_ec({Signed, Bin}) ->
    jwte:verify(Signed, ec_pub_pem(), Bin).

%% Sign EC
sign_ec(ec512) ->
    jwte:sign(claims_map(), ec_pri_pem(), <<"EC512">>).

grp_HMAC() ->
    [{hs256, <<"HS256">>}, {hs384, <<"HS384">>}, {hs512, <<"HS512">>}].
grp_RSA() ->
    [{rs256, <<"RS256">>}, {rs384, <<"RS384">>}, {rs512, <<"RS512">>}].
grp_EC() ->
    [{ec512, <<"EC512">>}].

jwt(hs256) ->
    <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ">>;
jwt(hs384) ->
    <<"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.DtVnCyiYCsCbg8gUP-579IC2GJ7P3CtFw6nfTTPw-0lZUzqgWAo9QIQElyxOpoRm">>;
jwt(hs512) ->
    <<"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.YI0rUGDq5XdRw8vW2sDLRNFMN8Waol03iSFH8I4iLzuYK7FKHaQYWzPt0BJFGrAmKJ6SjY0mJIMZqNQJFVpkuw">>;
jwt(rs256) ->
    <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.R4_1G1Kwgc6R5sXI90WY8xvoJzODhKs14WUv1oMRWXUwpl_Gw4syktMyfkXcAIm-0p6w9Qv9sJ6ERguboLiQ80gDGtI7qHyBpuRNcCVVftgXZs35dmYV0_T6VRGVdNbcJJvlH1dv8Kps5viGW6whYzmZ8pe-Ve_kZSnlwztUo1kStuteCef-PKze6A9zqCdIKcG4l1JqgkfwYclUpUbiUHh1qSaWiyPiqwjrn6O6ht9bBsv6FmDq6ulcp0-0yZXOJDO6-BFdVI7eXkhPt4D7smlz2ceGLeMCD9y8xDCUYAvRT12n0seuEfpDvvFoW3MiEG3SIDg1LleStBg3T6nVsA">>;
jwt(rs384) ->
    <<"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.f52d9inW1kZg6Ccm0T_dYxH1TmC6Y7euwD6qNSP6H2tLOTDfVafRIOdUdoWllODcA8hAd8G9rX_sITe4GpmeVbRmvjMX9aR6yQM8KL42UFWSymW6sDMcE8hkUSsL1Obj0Z6efC9RAVHxkrgyBdWmnQS8V_ELEsV1-QeNGajkPINxYfZK6vW899v32OaBmw13q4xE84mRphJVkq103-Peyxaeph_OKWzf9wey_4ioY_J2v89BjDyB2M5Q_05M2lmxW37tbllzQXpYUSli8fu8OqPwJzBOZq3nTMtFj9sFHupH3NLh4IU8wefC-8GxlOOxFwFbax7ve7nThg0Cq4mvxg">>;
jwt(rs512) ->
    <<"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.KhaKNUGh2GpDW_AF45wfpq3Gi2LQdUkYBk4BXKswJ2RmqfCwTwK3ZwMAVLbrns0xSOJGX6RVXGZyAa4enpDWccgaGaz9EVgykWfJleKG0hSVXxPRArQ4b022ND34arHhFDIMwITEFT3mEkR9-VoAnLs0hxOWCaDjwMcpdTcJw3OYtkSqVLv1p-eZUcixsDu9Z94X18inFU83o4srK049XxVN9pfdvjfrGJF-P0pfoMCq3yeyBgtsXfzStnVhQfW7oTfvDXDLehYo3g888e5BlgxqFEo0IVzzWrMwNSBCpiXtmCNMgUseCmGPlSAMD9182fO6O6u2nXFvnCTQBeCqiA">>.


