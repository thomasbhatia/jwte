% -define(HS256, hs256).
% -define(HS384, hs384).
% -define(HS512, hs512).

% -define(HS256, <<"HS256">>).
% -define(HS384, <<"HS384">>).
% -define(HS512, <<"HS512">>).

% -define(RS256, <<"RS256">>).
% -define(RS384, <<"RS384">>).
% -define(RS512, <<"RS512">>).


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

% P = [
%   {<<"sub">>, <<"1234567890">>},
%   {<<"name">>, <<"John Doe">>},
%   {<<"admin">>, true}
% ].

% Z = jwte:sign(P, "secret", <<"HS384">>).
% io:format("~p",[Z]).

% Y = jwte:verify(Z, "secret").

% {ok, PriKeyPem} = file:read_file("test/rsakey_2048.pem").
% ZO=jwte:sign(P, PriKeyPem, <<"RS512">>).  
% io:format("~p",[ZO]).

% {ok, PublicKeyPem} = file:read_file("test/rsakey_2048_pub.pem").
% X = jwte:verify(ZK, PublicKeyPem, <<"RS256">>).



% 
% Z=
% io:format("~p",[Z]).

