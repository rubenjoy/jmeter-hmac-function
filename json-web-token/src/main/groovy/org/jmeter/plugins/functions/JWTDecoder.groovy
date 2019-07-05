package org.jmeter.plugins.functions

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT

import groovy.util.logging.Slf4j

import org.apache.jmeter.engine.util.CompoundVariable
import org.apache.jmeter.functions.AbstractFunction
import org.apache.jmeter.functions.InvalidVariableException
import org.apache.jmeter.samplers.SampleResult
import org.apache.jmeter.samplers.Sampler

import java.util.Collection

/**
 *  jmeter pplugin to decode JWT token and put the decoded token into
 *  variables.
 *
 *  parameters:
 *  <ul>
 *      <li>JWT Token</li>
 *      <li>Claim to fetch</li>
 *      <li>Algorithm to use</li>
 *      <li>Variable name to hold the fetched claim</li>
 *      <li>Variable name to hold decoded token object</li>
 *  </ul>
 */
 @Slf4j
public class JWTDecoder extends AbstractFunction {

    private static final List<String> desc = [
        'Encoded JWT token',
        'Claim',
        'variable for claim',
        'variable for claim map']

    private static final String KEY = '__jwtDecode'

    private List<CompoundVariable> values

    private static final int MAX_PARAM_COUNT = 4
    private static final int MIN_PARAM_COUNT = 2

    private static final int CLAIM_VARIABLE = 3
    private static final int TOKEN_VARIABLE = 4

    /**
     *  No-arg constructor.
     */
     public JWTDecoder() {
        super()
     }

     /** {@inheritDoc} */
     @Override
     public String execute(SampleResult prev, Sampler curr)
        throws InvalidVariableException {

        String token = values[0].execute().trim()
        String claimKey = values[1].execute().trim()

        String claimVariableName = ''
        if (values.size() >= CLAIM_VARIABLE) {
            claimVariableName = values[CLAIM_VARIABLE - 1].execute().trim()
        }

        String tokenVariableName = ''
        if (values.size() >= TOKEN_VARIABLE) {
            tokenVariableName = values[TOKEN_VARIABLE - 1].execute().trim()
        }

        // put it into a variable or stow it into _storedToken variable
        if (tokenVariableName.length() <= 0) {
            tokenVariableName = '_storedToken'
        }
        def vars = getVariables()
        def decodedToken = vars?.getObject(tokenVariableName) ?: decode(token)
        vars?.putObject(tokenVariableName, decodedToken)

        String claimValue = decodedToken?.getClaim(claimKey).asString()

        if (claimVariableName.length() > 0) {
            vars?.put(claimVariableName, claimValue)
        }

        return claimValue
     }

    private DecodedJWT decode(String token) {
        return JWT.decode(token)
    }

    private String getClaimValue(DecodedJWT decoded, String key) {
        return decoded.getClaim(key)?.asString()
    }

    /** {@inheritDoc} */
    @Override
    public void setParameters(Collection<CompoundVariable> parameters)
        throws InvalidVariableException {

        checkParameterCount(parameters, MIN_PARAM_COUNT, MAX_PARAM_COUNT)
        def token = parameters[0].execute().trim()
        if (token.length() <= 0) {
            throw new InvalidVariableException("empty JWT token.")
        }
        if (token.spit(".").length != 3) {
            throw new InvalidVariableException("JWT token length not equal 3. ")
        }
        def claimName = parameters[1].execute().trim()
        if (token.length() <= 0) {
            throw new InvalidVariableException("empty claim name.")
        }
        values = parameters.collect()
    }

    /** {@inheritDoc} */
    @Override
    public String getReferenceKey() {
        return KEY
    }

    /** {@inheritDoc} */
    @Override
    public List<String> getArgumentDesc() {
        return desc
    }
}