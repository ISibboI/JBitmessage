package de.flexiprovider.ec;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.ec.keys.ECPublicKey;

public final class ECTools {

    /**
     * Default constructor (private).
     */
    private ECTools() {
	// empty
    }

    /**
     * Check if the given {@link ECPublicKey} is valid.
     * 
     * @param ecPubKey
     *                the {@link ECPublicKey}
     * 
     * @return <tt>true</tt> if this key is a valid {@link ECPublicKey},
     *         <tt>false</tt> otherwise
     * @throws InvalidKeyException
     *                 if the public key has not been initialized with EC domain
     *                 parameters and thus is only available in encoded form.
     */
    public static boolean isValidPublicKey(ECPublicKey ecPubKey)
	    throws InvalidKeyException {
	Point q = ecPubKey.getW();
	return !q.isZero() && q.onCurve();
    }

}
