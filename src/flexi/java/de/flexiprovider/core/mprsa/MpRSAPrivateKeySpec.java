package de.flexiprovider.core.mprsa;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAPrivateCrtKeySpec;

public class MpRSAPrivateKeySpec extends RSAPrivateCrtKeySpec {

    private RSAOtherPrimeInfo[] otherP;

    public MpRSAPrivateKeySpec(FlexiBigInt n, FlexiBigInt e, FlexiBigInt d,
	    FlexiBigInt p, FlexiBigInt q, FlexiBigInt dP, FlexiBigInt dQ,
	    FlexiBigInt crtCoeff, RSAOtherPrimeInfo[] otherP) {
	super(n, e, d, p, q, dP, dQ, crtCoeff);
	this.otherP = otherP;
    }

    /**
     * @return the other primes
     */
    public RSAOtherPrimeInfo[] getOtherPrimeInfo() {
	return otherP;
    }

}
