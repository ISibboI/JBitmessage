package de.flexiprovider.pqc;

import de.flexiprovider.api.FlexiProvider;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2KeyFactory;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2KeyPairGenerator;
import de.flexiprovider.pqc.ecc.mceliece.McElieceFujisakiCipher;
import de.flexiprovider.pqc.ecc.mceliece.McElieceKeyFactory;
import de.flexiprovider.pqc.ecc.mceliece.McElieceKeyPairGenerator;
import de.flexiprovider.pqc.ecc.mceliece.McElieceKobaraImaiCipher;
import de.flexiprovider.pqc.ecc.mceliece.McEliecePKCS;
import de.flexiprovider.pqc.ecc.mceliece.McEliecePointchevalCipher;
import de.flexiprovider.pqc.ecc.niederreiter.NiederreiterCFSSignature;
import de.flexiprovider.pqc.ecc.niederreiter.NiederreiterKeyFactory;
import de.flexiprovider.pqc.ecc.niederreiter.NiederreiterKeyPairGenerator;
import de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPKCS;
import de.flexiprovider.pqc.hbc.cmss.CMSSKeyFactory;
import de.flexiprovider.pqc.hbc.cmss.CMSSKeyPairGenerator;
import de.flexiprovider.pqc.hbc.cmss.CMSSSignature;
import de.flexiprovider.pqc.hbc.gmss.GMSSKeyFactory;
import de.flexiprovider.pqc.hbc.gmss.GMSSKeyPairGenerator;
import de.flexiprovider.pqc.hbc.gmss.GMSSSignature;
import de.flexiprovider.pqc.ots.lm.LMOTSKeyPairGenerator;
import de.flexiprovider.pqc.ots.lm.LMOTSSignature;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSKeyFactory;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSKeyPairGenerator;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSSignature;
import de.flexiprovider.pqc.pflash.PFlashKeyFactory;
import de.flexiprovider.pqc.pflash.PFlashKeyPairGenerator;
import de.flexiprovider.pqc.pflash.PFlashSignature;
import de.flexiprovider.pqc.rainbow.RainbowKeyFactory;
import de.flexiprovider.pqc.rainbow.RainbowKeyPairGenerator;
import de.flexiprovider.pqc.rainbow.RainbowSignature;

/**
 * This class is the provider for cryptographic algorithms which are secure even
 * against quantum computer attacks (post-quantum cryptography).
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
 * import de.flexiprovider.pqc.FlexiPQCProvider;
 * 
 * Security.addProvider(new FlexiPQCProvider());
 * </pre>
 * 
 * The provider is registered statically by adding an entry to the
 * <tt>java.security</tt> properties file (usually
 * <tt>$JAVA_HOME/lib/security/java.security</tt>). See that file for
 * instructions.
 * 
 * <h4>Contents of the FlexiPQCProvider</h4>
 * 
 * <ul type=circle>
 * 
 * <li>Digital signatures:
 * <ul type = square>
 * <li><a href = ots/merkle/MerkleOTSSignature.html>Signature.MerkleOTS</a></li>
 * <li><a href =
 * ots/coronado/CoronadoOTSSignature.html>Signature.CoronadoOTS</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA1andWinternitzOTS_1</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA1andWinternitzOTS_2</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA1andWinternitzOTS_3</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA1andWinternitzOTS_4</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA256andWinternitzOTS_1</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA256andWinternitzOTS_2</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA256andWinternitzOTS_3</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA256andWinternitzOTS_4</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA384andWinternitzOTS_1</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA384andWinternitzOTS_2</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA384andWinternitzOTS_3</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA384andWinternitzOTS_4</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA512andWinternitzOTS_1</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA512andWinternitzOTS_2</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA512andWinternitzOTS_3</a></li>
 * <li><a href =
 * cmss/CMSSSignature.html>Signature.CMSSwithSHA512andWinternitzOTS_4</a></li>
 * <li><a href =
 * ecc/niederreiter/NiederreiterCFSSignature.html>Signature.NiederreiterCFS</a></li>
 * <li><a href = ntru/ntrusign/NTRUSign.html>Signature.NTRUSign</a></li>
 * </ul>
 * </li>
 * 
 * <li>Asymmetric (public key) encryption:
 * <ul type = square>
 * <li><a href = ecc/mceliece/McEliecePKCS.html>Cipher.McEliecePKCS</a></li>
 * <li><a href =
 * ecc/mceliece/McElieceFujisakiCipher.html>Cipher.McElieceFujisakiCipher</a></li>
 * <li><a href =
 * ecc/mceliece/McElieceKobaraImaiCipher.html>Cipher.McElieceKobaraImaiCipher
 * </a></li>
 * <li><a href = ecc/mceliece/McEliecePointchevalCipher.html>Cipher.
 * McEliecePointchevalCipher</a></li>
 * <li><a href =
 * ecc/niederreiter/NiederreiterPKCS.html>Cipher.NiederreiterPKCS</a></li>
 * <li><a href = ntru/ntrusves/NTRUSVES.html>Cipher.NTRUSVES</a></li>
 * </ul>
 * </li>
 * 
 * </ul>
 * 
 * @author <a href="mailto:info@flexiprovider.de">FlexiProvider group</a>.
 * @version 1.7.6
 */
public class FlexiPQCProvider extends FlexiProvider {

	/**
	 * Constructor. Register all algorithms for FlexiAPI and JCA.
	 */
	public FlexiPQCProvider() {
		super("FlexiPQC", 1.76, "");

		// ------------------------------------------------
		// register algorithms for FlexiAPI
		// ------------------------------------------------

		PQCRegistry.registerAlgorithms();

		// ------------------------------------------------
		// register algorithms for JCA/JCE
		// ------------------------------------------------

		registerMerkleOTS();
		registerCMSS();
		registerGMSS();
		registerMcEliece();
		registerNiederreiter();
		registerLMOTS();
		registerRainbow();
		registerPflash();
	}

	private void registerMerkleOTS() {
		add(KEY_FACTORY, MerkleOTSKeyFactory.class, new String[] { "MerkleOTS",
				MerkleOTSKeyFactory.OID });
		addReverseOID(KEY_FACTORY, "MerkleOTS", MerkleOTSKeyFactory.OID);

		// Merkle OTS with SHA1 and SHA1PRNG
		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.class, new String[] {
						"MerkleOTSwithSHA1andSHA1PRNG",
						MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "MerkleOTSwithSHA1andSHA1PRNG",
				MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.OID);
		add(SIGNATURE, MerkleOTSSignature.SHA1andSHA1PRNG.class, new String[] {
				"MerkleOTSwithSHA1andSHA1PRNG",
				MerkleOTSSignature.SHA1andSHA1PRNG.OID });
		addReverseOID(SIGNATURE, "MerkleOTSwithSHA1andSHA1PRNG",
				MerkleOTSSignature.SHA1andSHA1PRNG.OID);

		// Merkle OTS with SHA256 and SHA1PRNG (default)
		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA256andSHA1PRNG", "MerkleOTS",
						MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "MerkleOTSwithSHA256andSHA1PRNG",
				MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.OID);
		add(SIGNATURE, MerkleOTSSignature.SHA256andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA256andSHA1PRNG", "MerkleOTS",
						MerkleOTSSignature.SHA256andSHA1PRNG.OID });
		addReverseOID(SIGNATURE, "MerkleOTSwithSHA256andSHA1PRNG",
				MerkleOTSSignature.SHA256andSHA1PRNG.OID);

		// Merkle OTS with SHA384 and SHA1PRNG
		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA384andSHA1PRNG",
						MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "MerkleOTSwithSHA384andSHA1PRNG",
				MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.OID);
		add(SIGNATURE, MerkleOTSSignature.SHA384andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA384andSHA1PRNG",
						MerkleOTSSignature.SHA384andSHA1PRNG.OID });
		addReverseOID(SIGNATURE, "MerkleOTSwithSHA384andSHA1PRNG",
				MerkleOTSSignature.SHA384andSHA1PRNG.OID);

		// Merkle OTS with SHA512 and SHA1PRNG
		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA512andSHA1PRNG",
						MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "MerkleOTSwithSHA512andSHA1PRNG",
				MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.OID);
		add(SIGNATURE, MerkleOTSSignature.SHA512andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA512andSHA1PRNG",
						MerkleOTSSignature.SHA512andSHA1PRNG.OID });
		addReverseOID(SIGNATURE, "MerkleOTSwithSHA512andSHA1PRNG",
				MerkleOTSSignature.SHA512andSHA1PRNG.OID);
	}

	private void registerCMSS() {
		add(KEY_FACTORY, CMSSKeyFactory.class, new String[] { "CMSS",
				CMSSKeyFactory.OID });

		// CMSS with SHA1 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA1andWinternitzOTS_1",
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_1",
						CMSSSignature.SHA1andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA1andWinternitzOTS_1",
				CMSSSignature.SHA1andWinternitzOTS_1.OID);

		// CMSS with SHA1 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_2", "CMSS",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA1andWinternitzOTS_2",
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_2.OID);
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_2", "CMSS",
						CMSSSignature.SHA1andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA1andWinternitzOTS_2",
				CMSSSignature.SHA1andWinternitzOTS_2.OID);

		// CMSS with SHA1 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA1andWinternitzOTS_3",
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_3",
						CMSSSignature.SHA1andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA1andWinternitzOTS_3",
				CMSSSignature.SHA1andWinternitzOTS_3.OID);

		// CMSS with SHA1 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA1andWinternitzOTS_4",
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_4",
						CMSSSignature.SHA1andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA1andWinternitzOTS_4",
				CMSSSignature.SHA1andWinternitzOTS_4.OID);

		// CMSS with SHA256 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA256andWinternitzOTS_1",
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_1",
						CMSSSignature.SHA256andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA256andWinternitzOTS_1",
				CMSSSignature.SHA256andWinternitzOTS_1.OID);

		// CMSS with SHA256 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_2", "CMSS",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA256andWinternitzOTS_2",
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_2.OID);
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_2", "CMSS",
						CMSSSignature.SHA256andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA256andWinternitzOTS_2",
				CMSSSignature.SHA256andWinternitzOTS_2.OID);

		// CMSS with SHA256 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA256andWinternitzOTS_3",
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_3",
						CMSSSignature.SHA256andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA256andWinternitzOTS_3",
				CMSSSignature.SHA256andWinternitzOTS_3.OID);

		// CMSS with SHA256 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA256andWinternitzOTS_4",
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_4",
						CMSSSignature.SHA256andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA256andWinternitzOTS_4",
				CMSSSignature.SHA256andWinternitzOTS_4.OID);

		// CMSS with SHA384 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA384andWinternitzOTS_1",
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_1",
						CMSSSignature.SHA384andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA384andWinternitzOTS_1",
				CMSSSignature.SHA384andWinternitzOTS_1.OID);

		// CMSS with SHA384 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_2", "CMSS",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA384andWinternitzOTS_2",
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_2.OID);
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_2", "CMSS",
						CMSSSignature.SHA384andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA384andWinternitzOTS_2",
				CMSSSignature.SHA384andWinternitzOTS_2.OID);

		// CMSS with SHA384 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA384andWinternitzOTS_3",
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_3",
						CMSSSignature.SHA384andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA384andWinternitzOTS_3",
				CMSSSignature.SHA384andWinternitzOTS_3.OID);

		// CMSS with SHA384 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA384andWinternitzOTS_4",
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_4",
						CMSSSignature.SHA384andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA384andWinternitzOTS_4",
				CMSSSignature.SHA384andWinternitzOTS_4.OID);

		// CMSS with SHA512 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA512andWinternitzOTS_1",
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_1",
						CMSSSignature.SHA512andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA512andWinternitzOTS_1",
				CMSSSignature.SHA512andWinternitzOTS_1.OID);

		// CMSS with SHA512 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_2", "CMSS",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA512andWinternitzOTS_2",
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_2.OID);
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_2", "CMSS",
						CMSSSignature.SHA512andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA512andWinternitzOTS_2",
				CMSSSignature.SHA512andWinternitzOTS_2.OID);

		// CMSS with SHA512 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA512andWinternitzOTS_3",
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_3",
						CMSSSignature.SHA512andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA512andWinternitzOTS_3",
				CMSSSignature.SHA512andWinternitzOTS_3.OID);

		// CMSS with SHA512 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "CMSSwithSHA512andWinternitzOTS_4",
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_4",
						CMSSSignature.SHA512andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSSwithSHA512andWinternitzOTS_4",
				CMSSSignature.SHA512andWinternitzOTS_4.OID);

		// SWIFFT
		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX224andWinternitzOTS_1",
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX224andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_1",
						CMSSSignature.SWIFFTX224andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX224andWinternitzOTS_1",
				CMSSSignature.SWIFFTX224andWinternitzOTS_1.OID);

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_2",
						"CMSS2",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX224andWinternitzOTS_2",
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2.OID);
		add(SIGNATURE,
				CMSSSignature.SWIFFTX224andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_2",
						"CMSS2", CMSSSignature.SWIFFTX224andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX224andWinternitzOTS_2",
				CMSSSignature.SWIFFTX224andWinternitzOTS_2.OID);

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX224andWinternitzOTS_3",
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX224andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_3",
						CMSSSignature.SWIFFTX224andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX224andWinternitzOTS_3",
				CMSSSignature.SWIFFTX224andWinternitzOTS_3.OID);

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX224andWinternitzOTS_4",
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX224andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_4",
						CMSSSignature.SWIFFTX224andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX224andWinternitzOTS_4",
				CMSSSignature.SWIFFTX224andWinternitzOTS_4.OID);

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX256andWinternitzOTS_1",
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_1",
						CMSSSignature.SWIFFTX256andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX256andWinternitzOTS_1",
				CMSSSignature.SWIFFTX256andWinternitzOTS_1.OID);

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_2",
						"CMSS2",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX256andWinternitzOTS_2",
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2.OID);
		add(SIGNATURE,
				CMSSSignature.SWIFFTX256andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_2",
						"CMSS2", CMSSSignature.SWIFFTX256andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX256andWinternitzOTS_2",
				CMSSSignature.SWIFFTX256andWinternitzOTS_2.OID);

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX256andWinternitzOTS_3",
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_3",
						CMSSSignature.SWIFFTX256andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX256andWinternitzOTS_3",
				CMSSSignature.SWIFFTX256andWinternitzOTS_3.OID);

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX256andWinternitzOTS_4",
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_4",
						CMSSSignature.SWIFFTX256andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX256andWinternitzOTS_4",
				CMSSSignature.SWIFFTX256andWinternitzOTS_4.OID);

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX384andWinternitzOTS_1",
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_1",
						CMSSSignature.SWIFFTX384andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX384andWinternitzOTS_1",
				CMSSSignature.SWIFFTX384andWinternitzOTS_1.OID);

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_2",
						"CMSS2",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX384andWinternitzOTS_2",
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2.OID);
		add(SIGNATURE,
				CMSSSignature.SWIFFTX384andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_2",
						"CMSS2", CMSSSignature.SWIFFTX384andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX384andWinternitzOTS_2",
				CMSSSignature.SWIFFTX384andWinternitzOTS_2.OID);

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX384andWinternitzOTS_3",
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_3",
						CMSSSignature.SWIFFTX384andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX384andWinternitzOTS_3",
				CMSSSignature.SWIFFTX384andWinternitzOTS_3.OID);

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX384andWinternitzOTS_4",
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_4",
						CMSSSignature.SWIFFTX384andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX384andWinternitzOTS_4",
				CMSSSignature.SWIFFTX384andWinternitzOTS_4.OID);

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX512andWinternitzOTS_1",
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_1",
						CMSSSignature.SWIFFTX512andWinternitzOTS_1.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX512andWinternitzOTS_1",
				CMSSSignature.SWIFFTX512andWinternitzOTS_1.OID);

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_2",
						"CMSS2",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX512andWinternitzOTS_2",
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2.OID);
		add(SIGNATURE,
				CMSSSignature.SWIFFTX512andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_2",
						"CMSS2", CMSSSignature.SWIFFTX512andWinternitzOTS_2.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX512andWinternitzOTS_2",
				CMSSSignature.SWIFFTX512andWinternitzOTS_2.OID);

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX512andWinternitzOTS_3",
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_3",
						CMSSSignature.SWIFFTX512andWinternitzOTS_3.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX512andWinternitzOTS_3",
				CMSSSignature.SWIFFTX512andWinternitzOTS_3.OID);

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4.OID });
		addReverseOID(KEY_PAIR_GENERATOR,
				"CMSS2withSWIFFTX512andWinternitzOTS_4",
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4.OID);
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_4",
						CMSSSignature.SWIFFTX512andWinternitzOTS_4.OID });
		addReverseOID(SIGNATURE, "CMSS2withSWIFFTX512andWinternitzOTS_4",
				CMSSSignature.SWIFFTX512andWinternitzOTS_4.OID);

	}

	private void registerGMSS() {
		add(KEY_FACTORY, GMSSKeyFactory.class, new String[] { "GMSS",
				GMSSKeyFactory.OID });
		addReverseOID(KEY_FACTORY, "GMSS", GMSSKeyFactory.OID);

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA1.class,
				new String[] { "GMSSwithSHA1",
						GMSSKeyPairGenerator.GMSSwithSHA1.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "GMSSwithSHA1",
				GMSSKeyPairGenerator.GMSSwithSHA1.OID);
		add(SIGNATURE, GMSSSignature.GMSSwithSHA1.class, new String[] {
				"GMSSwithSHA1", GMSSKeyPairGenerator.GMSSwithSHA1.OID });
		addReverseOID(SIGNATURE, "GMSSwithSHA1", GMSSSignature.GMSSwithSHA1.OID);

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA224.class,
				new String[] { "GMSSwithSHA224",
						GMSSKeyPairGenerator.GMSSwithSHA224.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "GMSSwithSHA224",
				GMSSKeyPairGenerator.GMSSwithSHA224.OID);
		add(SIGNATURE, GMSSSignature.GMSSwithSHA224.class, new String[] {
				"GMSSwithSHA224", GMSSKeyPairGenerator.GMSSwithSHA224.OID });
		addReverseOID(SIGNATURE, "GMSSwithSHA224",
				GMSSSignature.GMSSwithSHA224.OID);

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA256.class,
				new String[] { "GMSSwithSHA256",
						GMSSKeyPairGenerator.GMSSwithSHA256.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "GMSSwithSHA256",
				GMSSKeyPairGenerator.GMSSwithSHA256.OID);
		add(SIGNATURE, GMSSSignature.GMSSwithSHA256.class, new String[] {
				"GMSSwithSHA256", GMSSKeyPairGenerator.GMSSwithSHA256.OID });
		addReverseOID(SIGNATURE, "GMSSwithSHA256",
				GMSSSignature.GMSSwithSHA256.OID);

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA384.class,
				new String[] { "GMSSwithSHA384",
						GMSSKeyPairGenerator.GMSSwithSHA384.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "GMSSwithSHA384",
				GMSSKeyPairGenerator.GMSSwithSHA384.OID);
		add(SIGNATURE, GMSSSignature.GMSSwithSHA384.class, new String[] {
				"GMSSwithSHA384", GMSSKeyPairGenerator.GMSSwithSHA384.OID });
		addReverseOID(SIGNATURE, "GMSSwithSHA384",
				GMSSSignature.GMSSwithSHA384.OID);

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA512.class,
				new String[] { "GMSSwithSHA512",
						GMSSKeyPairGenerator.GMSSwithSHA512.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "GMSSwithSHA512",
				GMSSKeyPairGenerator.GMSSwithSHA512.OID);
		add(SIGNATURE, GMSSSignature.GMSSwithSHA512.class, new String[] {
				"GMSSwithSHA512", GMSSKeyPairGenerator.GMSSwithSHA512.OID });
		addReverseOID(SIGNATURE, "GMSSwithSHA512",
				GMSSSignature.GMSSwithSHA512.OID);
	}

	private void registerMcEliece() {
		// McEliece PKCS
		add(KEY_PAIR_GENERATOR, McElieceKeyPairGenerator.class, new String[] {
				"McEliece", McElieceKeyFactory.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "McEliece", McElieceKeyFactory.OID);
		add(KEY_FACTORY, McElieceKeyFactory.class, new String[] { "McEliece",
				McElieceKeyFactory.OID });
		addReverseOID(KEY_FACTORY, "McEliece", McElieceKeyFactory.OID);

		add(CIPHER, McEliecePKCS.class, new String[] { "McEliece",
				"McEliecePKCS", McEliecePKCS.OID });
		addReverseOID(CIPHER, "McEliece", McEliecePKCS.OID);

		// CCA2 conversions
		add(KEY_PAIR_GENERATOR, McElieceCCA2KeyPairGenerator.class,
				new String[] { "McElieceCCA2", McElieceCCA2KeyFactory.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "McElieceCCA2",
				McElieceCCA2KeyFactory.OID);
		add(KEY_FACTORY, McElieceCCA2KeyFactory.class, new String[] {
				"McElieceCCA2", McElieceCCA2KeyFactory.OID });
		addReverseOID(KEY_FACTORY, "McElieceCCA2", McElieceCCA2KeyFactory.OID);

		add(CIPHER, McElieceFujisakiCipher.class, new String[] {
				"McElieceFujisakiCipher", McElieceFujisakiCipher.OID });
		addReverseOID(CIPHER, "McElieceFujisakiCipher",
				McElieceFujisakiCipher.OID);
		add(CIPHER, McEliecePointchevalCipher.class, new String[] {
				"McEliecePointchevalCipher", McEliecePointchevalCipher.OID });
		addReverseOID(CIPHER, "McEliecePointchevalCipher",
				McEliecePointchevalCipher.OID);
		add(CIPHER, McElieceKobaraImaiCipher.class, new String[] {
				"McElieceKobaraImaiCipher", McElieceKobaraImaiCipher.OID });
		addReverseOID(CIPHER, "McElieceKobaraImaiCipher",
				McElieceKobaraImaiCipher.OID);
	}

	private void registerNiederreiter() {
		// generic
		add(KEY_PAIR_GENERATOR, NiederreiterKeyPairGenerator.class,
				new String[] { "Niederreiter", NiederreiterKeyFactory.OID });
		addReverseOID(KEY_PAIR_GENERATOR, "Niederreiter",
				NiederreiterKeyFactory.OID);
		add(KEY_FACTORY, NiederreiterKeyFactory.class, new String[] {
				"Niederreiter", NiederreiterKeyFactory.OID });
		addReverseOID(KEY_FACTORY, "Niederreiter", NiederreiterKeyFactory.OID);

		// Niederreiter PKCS
		add(CIPHER, NiederreiterPKCS.class, new String[] { "Niederreiter",
				"NiederreiterPKCS", NiederreiterPKCS.OID });
		addReverseOID(CIPHER, "Niederreiter", NiederreiterPKCS.OID);

		// Niederreiter CFS signature
		add(SIGNATURE, NiederreiterCFSSignature.class,
				new String[] { "Niederreiter", "NiederreiterCFS",
						NiederreiterCFSSignature.OID });
		addReverseOID(SIGNATURE, "Niederreiter", NiederreiterCFSSignature.OID);
	}

	private void registerLMOTS() {
		add(SIGNATURE, LMOTSSignature.SHA1.class, new String[] {
				"SHA1withLMOTS", "SHA1/LMOTS" });
		add(SIGNATURE, LMOTSSignature.SHA224.class, new String[] {
				"SHA224withLMOTS", "SHA224/LMOTS" });
		add(SIGNATURE, LMOTSSignature.SHA256.class, new String[] {
				"SHA256withLMOTS", "SHA256/LMOTS" });
		add(SIGNATURE, LMOTSSignature.SHA384.class, new String[] {
				"SHA384withLMOTS", "SHA384/LMOTS" });
		add(SIGNATURE, LMOTSSignature.SHA512.class, new String[] {
				"SHA512withLMOTS", "SHA512/LMOTS" });
		add(SIGNATURE, LMOTSSignature.RIPEMD128.class, new String[] {
				"RIPEMD128withLMOTS", "RIPEMD128/LMOTS" });
		add(SIGNATURE, LMOTSSignature.RIPEMD160.class, new String[] {
				"RIPEMD160withLMOTS", "RIPEMD160/LMOTS" });
		add(SIGNATURE, LMOTSSignature.RIPEMD256.class, new String[] {
				"RIPEMD256withLMOTS", "RIPEMD256/LMOTS" });
		add(SIGNATURE, LMOTSSignature.RIPEMD320.class, new String[] {
				"RIPEMD320withLMOTS", "RIPEMD320/LMOTS" });
		add(KEY_PAIR_GENERATOR, LMOTSKeyPairGenerator.class, "LMOTS");
	}

	private void registerRainbow() {
		add(KEY_PAIR_GENERATOR, RainbowKeyPairGenerator.class, "Rainbow");
		add(KEY_FACTORY, RainbowKeyFactory.class, "Rainbow");

		add(SIGNATURE, RainbowSignature.class, "Rainbow");
	}

	private void registerPflash() {
		add(KEY_PAIR_GENERATOR, PFlashKeyPairGenerator.class, "PFlash");
		add(KEY_FACTORY, PFlashKeyFactory.class, "PFlash");

		add(SIGNATURE, PFlashSignature.class, "PFlash");
	}

}
