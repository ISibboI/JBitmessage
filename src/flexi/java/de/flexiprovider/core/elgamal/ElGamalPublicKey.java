/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements the PublicKey interface. It is normally instantiated
 * from ElGamalKeyPairGenerator. The public key consists of a modulus p (a
 * prime), a generator of (Zp/Z)* and the public value A = g<sup>a</sup> mod
 * p, a is the private exponent.
 * 
 * @see ElGamalKeyPairGenerator
 * @author Thomas Wahrenbruch
 */
public class ElGamalPublicKey extends PublicKey {

    /**
     * The prime modulus which specifies the group
     */
    private FlexiBigInt modulus;

    /**
     * A generator of <tt>(Zp/Z)*</tt>
     */
    private FlexiBigInt generator;

    /**
     * The public value <tt>A = g<sup>a</sup> mod modulus</tt>.
     */
    private FlexiBigInt publicA;

    /**
     * The constructor.
     * 
     * @param modulus -
     *                the prime modulus which specifies the group
     * @param generator -
     *                a generator of the group
     * @param publicA -
     *                the public value <tt>A = g<sup>a</sup> mod modulus</tt>
     */
    protected ElGamalPublicKey(FlexiBigInt modulus, FlexiBigInt generator,
	    FlexiBigInt publicA) {
	this.modulus = modulus;
	this.generator = generator;
	this.publicA = publicA;
    }

    /**
     * Construct an ElGamalPublicKey out of the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected ElGamalPublicKey(ElGamalPublicKeySpec keySpec) {
	this(keySpec.getModulus(), keySpec.getGenerator(), keySpec.getPublicA());
    }

    /**
     * Return the algorithm name.
     * 
     * @return "ElGamal"
     */
    public String getAlgorithm() {
	return "ElGamal";
    }

    /**
     * @return the prime modulus
     */
    public FlexiBigInt getModulus() {
	return modulus;
    }

    /**
     * @return the generator
     */
    public FlexiBigInt getGenerator() {
	return generator;
    }

    /**
     * @return the public value <tt>A = g<sup>a</sup> mod modulus</tt>
     */
    public FlexiBigInt getPublicA() {
	return publicA;
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	String result = "";
	result += "modulus  : 0x" + modulus.toString(16) + "\n";
	result += "generator: 0x" + generator.toString(16) + "\n";
	result += "public A : 0x" + publicA.toString(16) + "\n";

	return result;
    }

    public boolean equals(Object obj) {
	if (obj == null || !(obj instanceof ElGamalPublicKey)) {
	    return false;
	}

	ElGamalPublicKey otherKey = (ElGamalPublicKey) obj;

	boolean value = modulus.equals(otherKey.modulus);
	value &= generator.equals(otherKey.generator);
	value &= publicA.equals(otherKey.publicA);

	return value;
    }

    public int hashCode() {
	return modulus.hashCode() + generator.hashCode() + publicA.hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(ElGamalKeyFactory.OID);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	return new ASN1Null();
    }

    /**
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();
	keyData.add(ASN1Tools.createInteger(modulus));
	keyData.add(ASN1Tools.createInteger(generator));
	keyData.add(ASN1Tools.createInteger(publicA));
	return ASN1Tools.derEncode(keyData);
    }
}
