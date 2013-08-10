/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec;

/**
 * <tt>ECSVDPDH</tt> provides the implementation for key exchange with the
 * Diffie Hellman algorithm on elliptic curves over the general field with <i>p</i>
 * elements where p is an odd prime number.
 * <p>
 * This class implements the ECSVDP-DH primitive from IEEE 1363, i.e. the Diffie
 * Hellman algorithm without co-factor multiplication.
 * <p>
 * Usage:
 * 
 * <tt>kagA</tt> and <tt>kagB</tt> represent the parties trying to establish
 * a shared secret key, each with a private and public key. The following steps
 * have to be performed:
 * 
 * <pre>
 * KeyAgreement kagA = KeyAgreement.getInstance(&quot;ECDH&quot;, &quot;FlexiEC&quot;);
 * kagA.init(ecprivA, params, random);
 * KeyAgreement kagB = KeyAgreement.getInstance(&quot;ECDH&quot;, &quot;FlexiEC&quot;);
 * kagB.init(ecprivB, random);
 * ECSecretKey secrA = (ECSecretKey) kagA.doPhase(ecpubB, true);
 * ECSecretKey secrB = (ECSecretKey) kagB.doPhase(ecpubA, true);
 * </pre>
 * 
 * @author Jochen Hechler
 * @author Marcus St&ouml;gbauer
 */
public class ECSVDPDH extends ECSVDPDHC {

    public ECSVDPDH() {
	// no cofactor multiplication
	withCoFactor = false;
    }

}
