/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec;

import de.flexiprovider.api.FlexiProvider;
import de.flexiprovider.ec.keys.ECKeyFactory;
import de.flexiprovider.ec.keys.ECKeyPairGenerator;
import de.flexiprovider.ec.parameters.ECParameters;

/**
 * This class is the provider for the public key algorithms based on elliptic
 * curves.
 * 
 * <h4>Provider registration</h4>
 * 
 * Using this provider via the JCA requires runtime registration or static
 * registration of the provider.
 * <p>
 * To add the provider at runtime, use:
 * 
 * <pre>
 * import java.security.Security;
 * import de.flexiprovider.ec.FlexiECProvider;
 * 
 * Security.addProvider(new FlexiECProvider());
 * </pre>
 * 
 * The provider is registered statically by adding an entry to the
 * <tt>java.security</tt> properties file (usually
 * <tt>$JAVA_HOME/lib/security/java.security</tt>). See that file for
 * instructions.
 * 
 * <h4>Contents of the FlexiECProvider</h4>
 * 
 * <ul type="square">
 * 
 * <li>Digital signatures:
 * <ul type="circle">
 * <li><a href = ECDSASignature$SHA1.html>Signature.SHA1withECDSA</a></li>
 * <li><a href = ECDSASignature$SHA224.html>Signature.SHA224withECDSA</a></li>
 * <li><a href = ECDSASignature$SHA256.html>Signature.SHA256withECDSA</a></li>
 * <li><a href = ECDSASignature$SHA384.html>Signature.SHA384withECDSA</a></li>
 * <li><a href = ECDSASignature$SHA512.html>Signature.SHA512withECDSA</a></li>
 * <li><a href = ECDSASignature$Raw.html>Signature.RawECDSA</a></li>
 * <li><a href = ECNRSignature.html>Signature.SHA1withECNR</a></li>
 * </ul>
 * </li>
 * 
 * <li>Key agreement:
 * <ul type="circle">
 * <li><a href = ECSVDPDH.html>KeyAgreement.ECSVDPDH</a></li>
 * </ul>
 * </li>
 * 
 * <li>Asymmetric (public key) encryption:
 * <ul type="circle">
 * <li><a href = ecies/ECIES.html>Cipher.ECIES</a></li>
 * </ul>
 * </li>
 * 
 * <li>Pseudo random number generators:
 * <ul type="circle">
 * <li><a href = ecprng.ECPRNG.html>SecureRandom.ECPRNG</a></li>
 * </ul>
 * </li>
 * 
 * </ul>
 * 
 * @author <a href="mailto:info@flexiprovider.de">FlexiProvider group</a>.
 * @version 1.7.6
 */
public class FlexiECProvider extends FlexiProvider {

    private static final String INFO = "ECDSA, ECNR, ECDH, and ECIES";

    /**
     * Constructor. Register all algorithms for FlexiAPI and JCA.
     */
    public FlexiECProvider() {
	super("FlexiEC", 1.76, INFO);

	// ------------------------------------------------
	// register algorithms for FlexiAPI
	// ------------------------------------------------

	ECRegistry.registerAlgorithms();

	// ------------------------------------------------
	// register algorithms for JCA/JCE
	// ------------------------------------------------

	registerCommon();
	registerECDSA();
	registerECNR();
	registerECSVDPDH();
	registerECIES();
	registerECPRNG();
    }

    private void registerCommon() {
	add(KEY_PAIR_GENERATOR, ECKeyPairGenerator.class, new String[] { "EC",
		"ECDSA", "ECNR", "ECIES", "ECDH", ECKeyFactory.OID });
	addReverseOID(KEY_PAIR_GENERATOR, "EC", ECKeyFactory.OID);

	add(KEY_FACTORY, ECKeyFactory.class, new String[] { "EC", "ECDSA",
		"ECNR", "ECIES", "ECDH", ECKeyFactory.OID });
	addReverseOID(KEY_FACTORY, "EC", ECKeyFactory.OID);

	add(ALG_PARAMS, ECParameters.class, new String[] { "EC",
		ECParameters.OID, ECKeyFactory.OID, "ECDSA", "SHA1withECDSA",
		"SHA1/ECDSA", ECDSASignature.SHA1.OID, "SHA224withECDSA",
		"SHA224/ECDSA", ECDSASignature.SHA224.OID, "SHA256withECDSA",
		"SHA256/ECDSA", ECDSASignature.SHA256.OID, "SHA384withECDSA",
		"SHA384/ECDSA", ECDSASignature.SHA384.OID, "SHA512withECDSA",
		"SHA512/ECDSA", ECDSASignature.SHA512.OID, "RawECDSA",
		"RAWECDSA", "ECNR", "SHA1withECNR", "SHA1/ECNR", "ECDH" });
	addReverseOID(ALG_PARAMS, "EC", ECParameters.OID);
    }

    private void registerECDSA() {
	add(SIGNATURE, ECDSASignature.SHA1.class,
		new String[] { "SHA1withECDSA", "ECDSA", "SHA1/ECDSA",
			ECDSASignature.SHA1.OID });
	addReverseOID(SIGNATURE, "SHA1withECDSA", ECDSASignature.SHA1.OID);

	add(SIGNATURE, ECDSASignature.SHA224.class, new String[] {
		"SHA224withECDSA", "SHA224/ECDSA", ECDSASignature.SHA224.OID });
	addReverseOID(SIGNATURE, "SHA224withECDSA", ECDSASignature.SHA224.OID);

	add(SIGNATURE, ECDSASignature.SHA256.class, new String[] {
		"SHA256withECDSA", "SHA256/ECDSA", ECDSASignature.SHA256.OID });
	addReverseOID(SIGNATURE, "SHA256withECDSA", ECDSASignature.SHA256.OID);

	add(SIGNATURE, ECDSASignature.SHA384.class, new String[] {
		"SHA384withECDSA", "SHA384/ECDSA", ECDSASignature.SHA384.OID });
	addReverseOID(SIGNATURE, "SHA384withECDSA", ECDSASignature.SHA384.OID);

	add(SIGNATURE, ECDSASignature.SHA512.class, new String[] {
		"SHA512withECDSA", "SHA512/ECDSA", ECDSASignature.SHA512.OID });
	addReverseOID(SIGNATURE, "SHA512withECDSA", ECDSASignature.SHA512.OID);

	add(SIGNATURE, ECDSASignature.Raw.class, new String[] { "RawECDSA",
		"RAWECDSA" });
    }

    private void registerECNR() {
	add(SIGNATURE, ECNRSignature.class, new String[] { "ECNR",
		"SHA1withECNR", "SHA1/ECNR" });
    }

    private void registerECIES() {
	add(CIPHER, ECIES.class, new String[] { "ECIES", "IES" });
    }

    private void registerECSVDPDH() {
	add(KEY_AGREEMENT, ECSVDPDH.class, "ECSVDPDH");
	add(KEY_AGREEMENT, ECSVDPDHC.class, new String[] { "ECSVDPDHC", "EC",
		"ECDH" });
    }

    private void registerECPRNG() {
	add(SECURE_RANDOM, ECPRNG.class, "ECPRNG");
    }

}
