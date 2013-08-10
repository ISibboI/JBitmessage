package de.flexiprovider.pqc.pflash;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.math.finitefields.GF2Polynomial;
import de.flexiprovider.common.math.linearalgebra.GF2mMatrix;
import de.flexiprovider.common.math.linearalgebra.GF2mVector;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class implements the pFLASH private key.
 *
 * @author Marian Hornschuch, Alexander Koller
 * @see PFlashKeyPairGenerator
 */
public class PFlashPrivateKey extends PrivateKey {
    
    // the OID of the algorithm
    private final String oid = "pFLASH";
        
    // map S = M_S + c_S
    private GF2mMatrix m_S;
    
    private GF2mVector c_S;

    // map T = M_T + c_T
    private GF2mMatrix m_T;
    
    private GF2mVector c_T;
    
    // field polynomial of GF(2^(4*96))
    private GF2Polynomial poly_384;
    
    /**
     * Construct a new pFLASH private key.<p><b>The key contains:</b></p>
     * map S(x) = M<sub>S</sub>(x) + c<sub>S</sub><br/>
     * map T(x) = M<sub>T</sub>(x) + c<sub>T</sub><br/>
     * field polynomial of GF(2<sup>4*96</sup>)<p>
     * 
     * @param m_S
     * 		Matrix of map S
     * @param c_S
     * 		Vector of map S
     * @param m_T
     * 		Matrix of map T
     * @param c_T
     * 		Vector of map T
     * @param poly_384
     * 		field polynomial of GF(2<sup>384</sup>)
     */
    protected PFlashPrivateKey(GF2mMatrix m_S, GF2mVector c_S,
	    GF2mMatrix m_T, GF2mVector c_T, GF2Polynomial poly_384) {
	this.m_S = m_S;
	this.c_S = c_S;
	this.m_T = m_T;
	this.c_T = c_T;
	this.poly_384 = poly_384;
    }
    
    /**
     * Construct a new pFLASH private key from the given key specification
     * 
     * @param keySpec
     * 			a {@link PFlashPrivateKeySpec}
     */
    protected PFlashPrivateKey(PFlashPrivateKeySpec keySpec) {
	this(keySpec.getM_S(), keySpec.getC_S(), keySpec.getM_T(), keySpec.getC_T(), keySpec.getPoly_384());
    }

    /**
     * Compare this key with another object.
     * 
     * @param other
     * 			the other object
     * @return true if both are equal
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof PFlashPrivateKey)) {
	    return false;
	}
	
	PFlashPrivateKey otherKey = (PFlashPrivateKey) other;
	
	boolean result = oid.equals(otherKey.oid);
	
	result &= ByteUtils.equals(getKeyData(), otherKey.getKeyData());
	
	return result;
    }

    /**
     * @return "pFLASH"
     */
    public String getAlgorithm() {
	return "pFLASH";
    }

    protected String getOIDString() {
	return oid;
    }
    
    public GF2mMatrix getM_S() {
	return m_S;
    }
    
    public GF2mVector getC_S() {
	return c_S;
    }
    
    public GF2mMatrix getM_T() {
	return m_T;
    }
    
    public GF2mVector getC_T() {
	return c_T;
    }
    
    public GF2Polynomial getPoly_384() {
	return poly_384;
    }
    
    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return m_S.hashCode()+c_S.hashCode()+m_T.hashCode()+c_T.hashCode()
		+poly_384.hashCode();
    }
    
    /**
     * Not supported
     */
    public String toString() {
	return "";
    }
    
    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(PFlashKeyFactory.OID);
    }   
    
    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     * 	       structure
     */
    protected ASN1Type getAlgParams() {
	return new ASN1Null();
    }
    
    /**
     * @return the keyData to encode in the SubjectKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();
	
	// encode OID string
	keyData.add(new ASN1ObjectIdentifier(oid));
	
	ASN1SequenceOf keySequence = new ASN1SequenceOf(ASN1OctetString.class);
	keySequence.add(new ASN1OctetString(m_S.getEncoded()));
	keySequence.add(new ASN1OctetString(c_S.getEncoded()));
	keySequence.add(new ASN1OctetString(m_T.getEncoded()));
	keySequence.add(new ASN1OctetString(c_T.getEncoded()));
	keySequence.add(new ASN1OctetString(poly_384.toByteArray()));
	keyData.add(keySequence);
	
	return ASN1Tools.derEncode(keyData);
	}
}