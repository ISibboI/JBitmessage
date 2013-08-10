package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.pqc.hbc.PRNG;

public class PRNGWrapper implements PRNG {
    
    // the wrapped prng
    private PRNG rng;
    
    //the output length in byte
    private int length;
 
    
    public PRNGWrapper(PRNG prng, int length) {
	this.rng = prng;
	setLength(length);
    }

    public void initialize(MessageDigest md) {
	rng.initialize(md);
    }

    /**
     * returns the next output cut to the desired byte-length
     */
    public byte[] nextSeed(byte[] outSeed) {
	byte[] tmp = rng.nextSeed(outSeed);
	byte[] result = new byte[getLength()];
	
	if (tmp.length >= getLength()) {
	    System.arraycopy(tmp, 0, result, 0, getLength());
	} else {
	    // the digest must be extended (insecure)
	    System.arraycopy(tmp, 0, result, getLength()-tmp.length-1, tmp.length);
	}
	return result;
    }

    public void setLength(int length) {
	this.length = length;
    }

    public int getLength() {
	return length;
    }

}
