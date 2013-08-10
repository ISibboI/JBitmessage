package de.flexiprovider.core.mprsa;

import de.flexiprovider.common.math.FlexiBigInt;

public class RSAOtherPrimeInfo {

    private FlexiBigInt prime;
    private FlexiBigInt primeExponent;
    private FlexiBigInt crtCoefficient;

    public RSAOtherPrimeInfo(FlexiBigInt prime, FlexiBigInt primeExponent,
	    FlexiBigInt crtCoefficient) {
	this.prime = prime;
	this.primeExponent = primeExponent;
	this.crtCoefficient = crtCoefficient;

    }

    public final FlexiBigInt getPrime() {
	return prime;
    }

    public final FlexiBigInt getExponent() {
	return primeExponent;
    }

    public final FlexiBigInt getCrtCoefficient() {
	return crtCoefficient;
    }

}
