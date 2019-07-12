package org.jmeter.plugins.functions;

import org.apache.jmeter.engine.util.CompoundVariable;
import org.apache.jmeter.functions.AbstractFunction;
import org.apache.jmeter.functions.InvalidVariableException;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.samplers.Sampler;
import org.apache.jmeter.threads.JMeterVariables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 *  JMeter plugin provides HMAC function
 */
public class HmacFunction extends  AbstractFunction {

    private static final Logger log = LoggerFactory.getLogger(HmacFunction.class);

    private static final List<String> desc = new LinkedList<>();

    private static final String KEY = "__HMAC";

    static {
        desc.add("plaintext");
        desc.add("key");
        desc.add("algorithm, HmacMD5|HmacSHA1HmacSHA256");
        desc.add("variable_name");
    }

    private CompoundVariable[] values;

    private static final int MAX_PARAM_COUNT = 4;

    private static final int MIN_PARAM_COUNT = 2;

    private static final int ALGORITHM = 3;

    private static final int VAR_NAME = 4;

    /**
     * No-arg constructor.
     */
    public HmacFunction() {
        super();
    }

    /**
     *  compute hmac value
     *  @param plaintext message
     *  @param key
     *  @param algo rithm to choose HmacSHA256, HmacSHA512
     */
    private String hmac(String plaintext, String key, String algo) {

        try {
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), algo);
            Mac mac = Mac.getInstance(algo);
            mac.init(keySpec);

            byte[] bytes = mac.doFinal(plaintext.getBytes("ASCII"));

            StringBuffer hash = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {
                String hex = Integer.toHexString(0xff & bytes[i]);
                if (hex.length() == 1) {
                    hash.append("0");
                }
                hash.append(hex);
            }

            return hash.toString();
        } catch (UnsupportedEncodingException e) {
            log.error(e.getMessage());
        } catch (InvalidKeyException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            if (log.isDebugEnabled()) {
                e.printStackTrace();
            }
        }
        return "";
    }

    /** {@inheritDoc} */
    @Override
    public String execute(SampleResult previousResult, Sampler currentSampler) throws InvalidVariableException {
        String plaintext = values[0].execute();
        String key = values[1].execute();

        String algorithm = "HmacSHA256";
        if (values.length >= ALGORITHM) {
            algorithm = (values[ALGORITHM - 1]).execute().trim();
            if (algorithm.length() <= 0) {
                algorithm = "HmacSHA256";
            }
        }

        String name = "";
        if (values.length >= VAR_NAME) {
            name = (values[VAR_NAME - 1]).execute().trim();
        }

        String value = hmac(plaintext, key, algorithm);
        if (log.isDebugEnabled()) {
            log.debug("{} name: {} value: {}", Thread.currentThread().getName(), name, value);
        }

        if (name.length() > 0) {
            JMeterVariables vars = getVariables();
            if (vars != null) {
                vars.put(name, value);
            }
        }

        return value;
    }

    /** {@inheritDoc} */
    @Override
    public void setParameters(Collection<CompoundVariable> parameters) throws InvalidVariableException {
        checkParameterCount(parameters, MIN_PARAM_COUNT, MAX_PARAM_COUNT);
        values = parameters.toArray(new CompoundVariable[parameters.size()]);
    }

    /** {@inheritDoc} */
    @Override
    public String getReferenceKey() {
        return KEY;
    }

    /** {@inheritDoc} */
    @Override
    public List<String> getArgumentDesc() {
        return desc;
    }
}
