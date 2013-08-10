package de.flexiprovider.core.mersa;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAPrivateCrtKeySpec;

public class MeRSAPrivateKeySpec extends RSAPrivateCrtKeySpec {

    private FlexiBigInt k, eInvP;

    public MeRSAPrivateKeySpec(FlexiBigInt n, FlexiBigInt e, FlexiBigInt d,
	    FlexiBigInt p, FlexiBigInt q, FlexiBigInt dP, FlexiBigInt dQ,
	    FlexiBigInt crtCoeff, FlexiBigInt k, FlexiBigInt eInvP) {
	super(n, e, d, p, q, dP, dQ, crtCoeff);
	this.k = k;
	this.eInvP = eInvP;
    }

    /**
     * @return the exponent k
     */
    public FlexiBigInt getK() {
	return k;
    }

    /**
     * @return the inverse of the public exponent modulo p
     */
    public FlexiBigInt getEInvP() {
	return eInvP;
    }

}
