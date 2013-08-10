package de.flexiprovider.core.kdf;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class specifies parameters used by the {@link KDF1}, {@link KDF2}, and
 * {@link X963} key derivation functions. The parameters consist of a byte array
 * containing shared information.
 * 
 * @author Martin Döring
 */
public class KDFParameterSpec implements AlgorithmParameterSpec {

    // the shared information
    private byte[] sharedInfo;

    /**
     * Constructor. Set the shared information.
     * 
     * @param sharedInfo
     *                the shared information
     */
    public KDFParameterSpec(byte[] sharedInfo) {
	this.sharedInfo = ByteUtils.clone(sharedInfo);
    }

    /**
     * @return the shared information
     */
    public byte[] getSharedInfo() {
	return ByteUtils.clone(sharedInfo);
    }

}
