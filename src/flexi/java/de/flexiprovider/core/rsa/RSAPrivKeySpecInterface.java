package de.flexiprovider.core.rsa;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

interface RSAPrivKeySpecInterface extends KeySpec {

    /**
     * @return the modulus n
     */
    FlexiBigInt getN();

    /**
     * @return the private exponent d
     */
    FlexiBigInt getD();

}
