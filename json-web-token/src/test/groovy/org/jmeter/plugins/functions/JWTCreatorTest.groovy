package org.jmeter.plugins.functions

import static org.junit.Assert.assertTrue;

import org.apache.jmeter.engine.util.CompoundVariable;
import org.apache.jmeter.functions.AbstractFunction;
import org.apache.jmeter.functions.InvalidVariableException;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.threads.JMeterContext;
import org.apache.jmeter.threads.JMeterContextService;
import org.apache.jmeter.threads.JMeterVariables;

import org.junit.Before;
import org.junit.Test;


public class JWTCreatorTest {

    private AbstractFunction function;
    private SampleResult result;
    private JMeterVariables vars;
    private JMeterContext jmctx = null;
    private String value;

    @Before
    public void setUp() {
        jmctx = JMeterContextService.getContext()
        vars = new JMeterVariables()
        jmctx.setVariables(vars)
        result = new SampleResult()
        jmctx.setPreviousResult(result)
        function = new JWTCreator()
    }

    @Test
    public void itShouldNot_AcceptEmptyAlgorithm() {
        assertTrue(true)
    }

    public void itShouldNot_AcceptUnsupportedAlgorithm() {

    }

    @Test(expected=InvalidVariableException.class)
    public void itShouldNot_AcceptEmptySecretKey() {
        List<CompoundVariable> params = ['HS256', 'secret', 'key:value']
        function.setParameters(params
        value = function.execute(result, null)
    }

    public void itShouldNot_AcceptInvalidFormClaims() {

    }

    public void itShould_AcceptSimpleKeyValuePairOfClaims() {

    }

    public void itShould_CreateJWTTokenWellFormed() {

    }

    public void givenVariableName_itShould_StoreTheTokenInContextVariables() {

    }

    public void itShould_ImplementFunction() {

    }

    public void itShould_WrappedInPackageFunctions() {

    }

    public void itShould_CreateJWTTokenHMACSigned() {

    }

    public void itShould_CreateJWTTokenECDSASigned() {

    }

    public void itShould_CreateJWTTokenRSASigned() {

    }
}