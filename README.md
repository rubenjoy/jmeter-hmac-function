# JMeter Plugins

Collection of plugins in this repository:

 - HMAC function
 - Decode JWT token function
 - JWT encode function that transform set of claims into JWT token
 - Assert JWT Token

## HMAC Function

A JMeter function that give HMAC value with given parameters:

 - __message__ to be hashed
 - __key__ to hash the message
 - __algorithm__ function to choose, which is optional

## JWT Decoder

A JMeter function that give claim value from JWT token payload, with set of given parameters:

 - __token__ encoded with format _header.payload.signature_
 - __claim name__ the key which is member of JSON payload

This function will decode the token without validating the token first.

## Issue JWT Token

This plugins can encode a JSON payload containing claims into JWT token. EIther _jwtCreate_ function or _JWTGenerator_ class as Java Request can do that.

## JwT Verifier

JMeter assertion that verify a token contains all required claims. Required parameters for this function:

 - __token__ encoded JWT
 - __verifiers__ comma separated claim which is pair of key and claim value, e.g.: iss:auth0,scope:operator value will validate the token contains two claims iss and scope.

## Notes

 - to build plugin: change to plugin directory then gradle build
 - to install plugin: put the related plugins into $JMETER_HOME/lib/ext