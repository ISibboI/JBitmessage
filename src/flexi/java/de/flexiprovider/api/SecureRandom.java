package de.flexiprovider.api;

import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.util.BigEndianConversions;

public abstract class SecureRandom extends java.security.SecureRandomSpi {

    protected final byte[] engineGenerateSeed(int numBytes) {
	return generateSeed(numBytes);
    }

    protected final void engineNextBytes(byte[] bytes) {
	nextBytes(bytes);
    }

    protected final void engineSetSeed(byte[] seed) {
	setSeed(seed);
    }

    public abstract byte[] generateSeed(int numBytes);

    public abstract void nextBytes(byte[] bytes);

    public abstract void setSeed(byte[] seed);

    public final int nextInt() {
	byte[] intBytes = new byte[4];
	nextBytes(intBytes);
	return BigEndianConversions.OS2IP(intBytes);
    }

    public final int nextInt(int upperBound) {
	int result;
	int octL = IntegerFunctions.ceilLog256(upperBound);
	do {
	    byte[] intBytes = new byte[octL];
	    nextBytes(intBytes);
	    result = BigEndianConversions.OS2IP(intBytes, 0, octL);
	} while (result < 0 || result >= upperBound);
	return result;
    }

}
