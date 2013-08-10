/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal.semanticallysecure;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.core.elgamal.ElGamalKeyFactory;

/**
 * This class implements the PublicKey interface. It is normally instantiated
 * from SSVElGamalKeyPairGenerator. The public key consists of a modulus p (a
 * prime), a modulus q (prime), a generator of (Zp/Z)* and the public value A =
 * g<sup>a</sup> mod p, a is the private exponent.
 * 
 * @see SSVElGamalKeyPairGenerator
 * 
 * @author Thomas Wahrenbruch
 * @author Roberto Samarone dos Santos Araújo
 * 
 */
public class SSVElGamalPublicKey extends PublicKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = 76078474797857792L;

	/**
	 * The prime modulus p which specifies the group
	 */
	private FlexiBigInt modulusP;

	/**
	 * The prime modulus q which specifies the subgroup
	 */

	private FlexiBigInt modulusQ;

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
	 * @param modulusp
	 *            - the prime modulus which specifies the group
	 * @param modulusq
	 *            - the prime modulus which specifies the subgroup
	 * @param generator
	 *            - a generator of the group
	 * @param publicA
	 *            - the public value <tt>A = g<sup>a</sup> mod modulus</tt>
	 */
	protected SSVElGamalPublicKey(FlexiBigInt modulusp, FlexiBigInt modulusq,
			FlexiBigInt generator, FlexiBigInt publicA) {
		this.modulusP = modulusp;
		this.modulusQ = modulusq;
		this.generator = generator;
		this.publicA = publicA;
	}

	/**
	 * Construct an SSVElGamalPublicKey out of the given key specification.
	 * 
	 * @param keySpec
	 *            the key specification
	 */
	protected SSVElGamalPublicKey(SSVElGamalPublicKeySpec keySpec) {
		this(keySpec.getModulusP(), keySpec.getModulusQ(), keySpec
				.getGenerator(), keySpec.getPublicA());
	}

	/**
	 * Return the algorithm name.
	 * 
	 * @return "SSVElGamal"
	 */
	public String getAlgorithm() {
		return "SSVElGamal";
	}

	/**
	 * @return the prime modulus
	 */
	public FlexiBigInt getModulusP() {
		return modulusP;
	}

	public FlexiBigInt getModulusQ() {
		return modulusQ;
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
		result += "modulusp  : 0x" + modulusP.toString(16) + "\n";
		result += "modulusq  : 0x" + modulusQ.toString(16) + "\n";
		result += "generator: 0x" + generator.toString(16) + "\n";
		result += "public A : 0x" + publicA.toString(16) + "\n";

		return result;
	}

	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof SSVElGamalPublicKey)) {
			return false;
		}

		SSVElGamalPublicKey otherKey = (SSVElGamalPublicKey) obj;

		boolean value = modulusP.equals(otherKey.modulusP);
		value &= modulusQ.equals(otherKey.modulusQ);
		value &= generator.equals(otherKey.generator);
		value &= publicA.equals(otherKey.publicA);

		return value;
	}

	public int hashCode() {
		return modulusP.hashCode() + modulusQ.hashCode() + generator.hashCode()
				+ publicA.hashCode();
	}

	/**
	 * @return null
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
		keyData.add(ASN1Tools.createInteger(modulusP));
		keyData.add(ASN1Tools.createInteger(modulusQ));
		keyData.add(ASN1Tools.createInteger(generator));
		keyData.add(ASN1Tools.createInteger(publicA));
		return ASN1Tools.derEncode(keyData);
	}
}
