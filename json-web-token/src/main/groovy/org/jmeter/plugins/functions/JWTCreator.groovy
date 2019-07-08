package org.jmeter.plugins.functions

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm

import groovy.util.logging.Slf4j

import org.apache.jmeter.engine.util.CompoundVariable
import org.apache.jmeter.functions.AbstractFunction
import org.apache.jmeter.functions.InvalidVariableException
import org.apache.jmeter.samplers.SampleResult
import org.apache.jmeter.samplers.Sampler

import java.util.Collection

/**
 *  Parameters:
 *  <ul>
 *      <li>algorithm, single key not supporting keystore</li>
 *      <li>secret/private key</li>
 *      <li>claims should be in simple key-value pair</li>
 *  </ul>
 */
 @Slf4j
public class JWTCreator extends AbstractFunction {

    private static final List<String> desc = [
        'Algorithm HS256,HS384,HS512 | RS256,RS384,RS512 | ES256,ES384,ES512',
        'Secret key or encoded private key',
        'Claims in payload, simple key:string-value pair and comma separated',
        'Array Claims, simple key:array-value pair, comma separated OPTIONAL',
        'Variable name to stow the token OPTIONAL']

    private static final String FUNCTION_NAME = '__jwtCreate'

    private List<CompoundVariable> values

    private static final int MIN_PARAM_COUNT = 3
    private static final int MAX_PARAM_COUNT = 5

    private static final int ALGORITHM = 1
    private static final int KEY = 2
    private static final int CLAIMS = 3
    private static final int ARRAY_CLAIMS = 4
    private static final int VARIABLE_NAME = 5

    private static final List<String> SUPPORTED_ALGORITHMS = [
        'HS256', 'HS384', 'HS512', 'RS256', 'RS512', 'ES256', 'ES384', 'ES512'
    ]

    /**
     *  No-arg constructor.
     */
     public JWTCreator() {
        super()
     }

     /** {@inheritDoc} */
     @Override
     public String execute(SampleResult prev, Sampler curr)
        throws InvalidVariableException {

        def algorithm = values[ALGORITHM - 1].execute().trim()
        def key = values[KEY - 1].execute().trim()
        def claims = values[CLAIMS - 1].execute().trim()
        def arrayClaims = values[ARRAY_CLAIMS - 1].execute().trim()

        def algo = create(algorithm, key)
        def token = ''
        if (algo != null) {
            token = sign(algo, claims, arrayClaims)
        }

        if (values.size() >= VARIABLE_NAME) {
            def variableName = values[VARIABLE_NAME - 1].execute().trim()
            if (variableName.length() > 0) {
                def vars = getVariables()
                vars?.put(variableName, token)
            }
        }

        return token
     }

     /**
      *  should return an algorithm instance given:
      *  @param algorithm name
      *  @param secret key or encoded private key
      */
     private Algorithm create(String algorithm, String secret) {
        switch (algorithm) {
            case ~/^HS(256|384|512)$/:
                return createHMAC(algorithm[-3..-1], secret)
            case ~/^RS(256|384|512)$/:
                return createRSA(algorithm[-3..-1], secret)
            case ~/^ES(256|384|512)$/:
                return createECDSA(algorithm[-3..-1], secret)
            default:
                break
        }

        return null
     }

     private Algorithm createHMAC(String length, String key) {
        switch (length) {
            case ~/^256$/:
                return Algorithm.HMAC256(key)
            case ~/^384$/:
                return Algorithm.HMAC384(key)
            case ~/^512$/:
                return Algorithm.HMAC512(key)
            default:
                break
        }
        return null
     }

     private Algorithm createRSA(String length, String privateKey) {
        def rsaPrivateKey = null
        switch (length) {
            case ~/^256$/:
                return Algorithm.RSA256(rsaPrivateKey)
            case ~/^384$/:
                return Algorithm.RSA384(rsaPrivateKey)
            case ~/^512$/:
                return Algorithm.RSA512(rsaPrivateKey)
            default:
                break
        }
        return null
     }

     private Algorithm createECDSA(String length, String privateKey) {
        def dsaPrivateKey = null
        switch(length) {
            case ~/^256$/:
                return Algorithm.ECDSA256(dsaPrivateKey)
            case ~/^384$/:
                return Algorithm.ECDSA384(dsaPrivateKey)
            case ~/^512$/:
                return Algorithm.ECDSA512(dsaPrivateKey)
            default:
                break
        }
        return null
     }

     /**
      *  return a signed token
      *  @param claims in comma separated, with form key:claim_value
      */
     private String sign(Algorithm algorithm, String claims,
            String arrayClaims) {

        def builder = JWT.create()
        claims.findAll(/([^,:]+):([^,:]+)/) {
            _, key, claimValue -> builder.addClaim(key, claimValue)
        }
        arrayClaims.findAll(/([^,:]+):([^,:]+)/) {
            _, key, value -> builder.withArrayClaim(key, value.split(';'))
        }
        return builder.sign(algorithm)
    }

    /** {@inheritDoc} */
    @Override
    public void setParameters(Collection<CompoundVariable> variables)
        throws InvalidVariableException {

        checkParameterCount(variables, MIN_PARAM_COUNT, MAX_PARAM_COUNT)
        def algorithm = variables[ALGORITHM - 1].execute().trim()
        if (algorithm.length() <= 0) {
            throw new InvalidVariableException("empty algorithm.")
        }
        def isSupported = SUPPORTED_ALGORITHMS.any { it == algorithm }
        if (!isSupported) {
            throw new InvalidVariableException("${algorithm} not supported.")
        }
        def key = variables[KEY - 1].execute().trim()
        if (key.length() <= 0) {
            throw new InvalidVariableException("empty key/secret.")
        }
        variables[CLAIMS - 1].execute().trim().split(',').each {
            if (it.split(':').length != 2) {
                throw new InvalidVariableException("${it} invalid form.")
            }
        }
        variables[ARRAY_CLAIMS - 1].execute().trim().split(',').each {
            if (it.split(':').length != 2) {
                throw new InvalidVariableException("${it} invalid form.")
            }
        }
        values = variables.collect()
    }

    /** {@inheritDoc} */
    @Override
    public String getReferenceKey() {
        return FUNCTION_NAME
    }

    /** {@inheritDoc} */
    @Override
    public List<String> getArgumentDesc() {
        return desc
    }
}