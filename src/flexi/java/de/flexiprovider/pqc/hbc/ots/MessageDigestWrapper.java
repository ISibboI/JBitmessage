package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;

/**
 * 
 * Wraps the given message digest to realize a given output length 
 * 
 * @author Sarah
 *
 */

public class MessageDigestWrapper extends MessageDigest {
    
    // the wrapped message digest
    private MessageDigest md;
    
    // the output length in byte
    private int length;
    
    
    public MessageDigestWrapper(MessageDigest md, int length) {
	this.md = md;
	this.setLength(length);
	
    }
     
    
    public void setLength(int length) {
	this.length = length;
    }


    public int getLength() {
	return length;
    }


    /**
     * returns the message digest output cut to the desired byte-length
     */
    public byte[] digest() {
	byte[] result = new byte[getLength()];
	byte[] tmp = md.digest();
	if (tmp.length >= getLength()) {
	    System.arraycopy(tmp, 0, result, 0, getLength());
	} else {
	    // the digest must be extended (insecure)
	    System.arraycopy(tmp, 0, result, getLength()-tmp.length-1, tmp.length);
	}
	
	return result;
    }

    public int getDigestLength() {
	return getLength();
    }
    
    // all other calls are forwarded to the wrapped message digest

    public void reset() {
	md.reset();
    }

    public void update(byte input) {
	md.update(input);
    }

    public void update(byte[] input, int offset, int len) {
	md.update(input, offset, len);
    }
    
   

}
