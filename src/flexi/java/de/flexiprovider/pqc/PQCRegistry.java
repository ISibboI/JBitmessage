package de.flexiprovider.pqc;

import de.flexiprovider.api.Registry;
import de.flexiprovider.pqc.ecc.ECCKeyGenParameterSpec;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2KeyFactory;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2KeyPairGenerator;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2ParameterSpec;
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
import de.flexiprovider.pqc.hbc.cmss.CMSSParameterSpec;
import de.flexiprovider.pqc.hbc.cmss.CMSSSignature;
import de.flexiprovider.pqc.hbc.gmss.GMSSKeyFactory;
import de.flexiprovider.pqc.hbc.gmss.GMSSKeyPairGenerator;
import de.flexiprovider.pqc.hbc.gmss.GMSSParameterSpec;
import de.flexiprovider.pqc.hbc.gmss.GMSSSignature;
import de.flexiprovider.pqc.ots.lm.LMOTSKeyPairGenerator;
import de.flexiprovider.pqc.ots.lm.LMOTSSignature;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSKeyFactory;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSKeyGenParameterSpec;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSKeyPairGenerator;
import de.flexiprovider.pqc.ots.merkle.MerkleOTSSignature;
import de.flexiprovider.pqc.pflash.PFlashKeyFactory;
import de.flexiprovider.pqc.pflash.PFlashKeyPairGenerator;
import de.flexiprovider.pqc.pflash.PFlashSignature;
import de.flexiprovider.pqc.rainbow.RainbowKeyFactory;
import de.flexiprovider.pqc.rainbow.RainbowKeyPairGenerator;
import de.flexiprovider.pqc.rainbow.RainbowSignature;

/**
 * Register all algorithms of the <a href="package.html">PQC package</a>.
 */
public abstract class PQCRegistry extends Registry {

	// flag indicating if algorithms already have been registered
	private static boolean registered;

	/**
	 * Register all algorithms of the <a href="package.html">PQC package</a>.
	 */
	public static void registerAlgorithms() {
		if (!registered) {
			registerMerkleOTS();
			registerCMSS();
			registerGMSS();
			registerMcEliece();
			registerNiederreiter();
			registerLMOTS();
			registerRainbow();
			registerPflash();
			registered = true;
		}
	}

	private static void registerMerkleOTS() {
		add(KEY_FACTORY, MerkleOTSKeyFactory.class, new String[] { "MerkleOTS",
				MerkleOTSKeyFactory.OID });

		add(ALG_PARAM_SPEC, MerkleOTSKeyGenParameterSpec.class, new String[] {
				"MerkleOTSKeyGen", "MerkleOTSwithSHA1KeyGen",
				MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.OID,
				"MerkleOTSwithSHA256KeyGen",
				MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.OID,
				"MerkleOTSwithSHA384KeyGen",
				MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.OID,
				"MerkleOTSwithSHA512KeyGen",
				MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.OID });

		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.class, new String[] {
						"MerkleOTSwithSHA1",
						MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.OID });
		add(SIGNATURE, MerkleOTSSignature.SHA1andSHA1PRNG.class, new String[] {
				"MerkleOTSwithSHA1", MerkleOTSSignature.SHA1andSHA1PRNG.OID });

		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.class,
				new String[] { "MerkleOTS", "MerkleOTSwithSHA256",
						MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.OID });
		add(SIGNATURE, MerkleOTSSignature.SHA256andSHA1PRNG.class,
				new String[] { "MerkleOTS", "MerkleOTSwithSHA256",
						MerkleOTSSignature.SHA256andSHA1PRNG.OID });

		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA384",
						MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.OID });
		add(SIGNATURE, MerkleOTSSignature.SHA384andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA384",
						MerkleOTSSignature.SHA384andSHA1PRNG.OID });

		add(KEY_PAIR_GENERATOR,
				MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA512",
						MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.OID });
		add(SIGNATURE, MerkleOTSSignature.SHA512andSHA1PRNG.class,
				new String[] { "MerkleOTSwithSHA512",
						MerkleOTSSignature.SHA512andSHA1PRNG.OID });
	}

	private static void registerCMSS() {
		add(KEY_FACTORY, CMSSKeyFactory.class, new String[] { "CMSS",
				CMSSKeyFactory.OID });

		add(ALG_PARAM_SPEC, CMSSParameterSpec.class, new String[] { "CMSS",
				"CMSSwithSHA1andWinternitzOTS_1",
				CMSSSignature.SHA1andWinternitzOTS_1.OID,
				"CMSSwithSHA1andWinternitzOTS_2",
				CMSSSignature.SHA1andWinternitzOTS_2.OID,
				"CMSSwithSHA1andWinternitzOTS_3",
				CMSSSignature.SHA1andWinternitzOTS_3.OID,
				"CMSSwithSHA1andWinternitzOTS_4",
				CMSSSignature.SHA1andWinternitzOTS_4.OID,
				"CMSSwithSHA256andWinternitzOTS_1",
				CMSSSignature.SHA256andWinternitzOTS_1.OID,
				"CMSSwithSHA256andWinternitzOTS_2",
				CMSSSignature.SHA256andWinternitzOTS_2.OID,
				"CMSSwithSHA256andWinternitzOTS_3",
				CMSSSignature.SHA256andWinternitzOTS_3.OID,
				"CMSSwithSHA256andWinternitzOTS_4",
				CMSSSignature.SHA256andWinternitzOTS_4.OID,
				"CMSSwithSHA384andWinternitzOTS_1",
				CMSSSignature.SHA384andWinternitzOTS_1.OID,
				"CMSSwithSHA384andWinternitzOTS_2",
				CMSSSignature.SHA384andWinternitzOTS_2.OID,
				"CMSSwithSHA384andWinternitzOTS_3",
				CMSSSignature.SHA384andWinternitzOTS_3.OID,
				"CMSSwithSHA384andWinternitzOTS_4",
				CMSSSignature.SHA384andWinternitzOTS_4.OID,
				"CMSSwithSHA512andWinternitzOTS_1",
				CMSSSignature.SHA512andWinternitzOTS_1.OID,
				"CMSSwithSHA512andWinternitzOTS_2",
				CMSSSignature.SHA512andWinternitzOTS_2.OID,
				"CMSSwithSHA512andWinternitzOTS_3",
				CMSSSignature.SHA512andWinternitzOTS_3.OID,
				"CMSSwithSHA512andWinternitzOTS_4",
				CMSSSignature.SHA512andWinternitzOTS_4.OID });

		// CMSS with SHA1 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_1",
						CMSSSignature.SHA1andWinternitzOTS_1.OID });

		// CMSS with SHA1 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_2", "CMSS",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_2", "CMSS",
						CMSSSignature.SHA1andWinternitzOTS_2.OID });

		// CMSS with SHA1 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_3",
						CMSSSignature.SHA1andWinternitzOTS_3.OID });

		// CMSS with SHA1 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA1andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA1andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SHA1andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA1andWinternitzOTS_4",
						CMSSSignature.SHA1andWinternitzOTS_4.OID });

		// CMSS with SHA256 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_1",
						CMSSSignature.SHA256andWinternitzOTS_1.OID });

		// CMSS with SHA256 and Winternitz OTS (w=2)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_2.class,
				new String[] { "CMSS", "CMSSwithSHA256andWinternitzOTS_2",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_2.class,
				new String[] { "CMSS", "CMSSwithSHA256andWinternitzOTS_2",
						CMSSSignature.SHA256andWinternitzOTS_2.OID });

		// CMSS with SHA256 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_3",
						CMSSSignature.SHA256andWinternitzOTS_3.OID });

		// CMSS with SHA256 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA256andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA256andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SHA256andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA256andWinternitzOTS_4",
						CMSSSignature.SHA256andWinternitzOTS_4.OID });

		// CMSS with SHA384 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_1",
						CMSSSignature.SHA384andWinternitzOTS_1.OID });

		// CMSS with SHA384 and Winternitz OTS (w=2)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_2",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_2",
						CMSSSignature.SHA384andWinternitzOTS_2.OID });

		// CMSS with SHA384 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_3",
						CMSSSignature.SHA384andWinternitzOTS_3.OID });

		// CMSS with SHA384 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA384andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA384andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SHA384andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA384andWinternitzOTS_4",
						CMSSSignature.SHA384andWinternitzOTS_4.OID });

		// CMSS with SHA512 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_1",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_1.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_1",
						CMSSSignature.SHA512andWinternitzOTS_1.OID });

		// CMSS with SHA512 and Winternitz OTS (w=2)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_2",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_2.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_2",
						CMSSSignature.SHA512andWinternitzOTS_2.OID });

		// CMSS with SHA512 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_3",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_3.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_3",
						CMSSSignature.SHA512andWinternitzOTS_3.OID });

		// CMSS with SHA512 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SHA512andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_4",
						CMSSKeyPairGenerator.SHA512andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SHA512andWinternitzOTS_4.class,
				new String[] { "CMSSwithSHA512andWinternitzOTS_4",
						CMSSSignature.SHA512andWinternitzOTS_4.OID });

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX224andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_1",
						CMSSSignature.SWIFFTX224andWinternitzOTS_1.OID });

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=2) (default)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_2",
						"CMSS2",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2.OID });
		add(
				SIGNATURE,
				CMSSSignature.SWIFFTX224andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_2",
						"CMSS2", CMSSSignature.SWIFFTX224andWinternitzOTS_2.OID });

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX224andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_3",
						CMSSSignature.SWIFFTX224andWinternitzOTS_3.OID });

		// CMSS2 with SWIFFTX224 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX224andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX224andWinternitzOTS_4",
						CMSSSignature.SWIFFTX224andWinternitzOTS_4.OID });

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_1",
						CMSSSignature.SWIFFTX256andWinternitzOTS_1.OID });

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=2)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2.class,
				new String[] { "CMSS2",
						"CMSS2withSWIFFTX256andWinternitzOTS_2",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_2.class,
				new String[] { "CMSS2",
						"CMSS2withSWIFFTX256andWinternitzOTS_2",
						CMSSSignature.SWIFFTX256andWinternitzOTS_2.OID });

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_3",
						CMSSSignature.SWIFFTX256andWinternitzOTS_3.OID });

		// CMSS2 with SWIFFTX256 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX256andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX256andWinternitzOTS_4",
						CMSSSignature.SWIFFTX256andWinternitzOTS_4.OID });

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_1",
						CMSSSignature.SWIFFTX384andWinternitzOTS_1.OID });

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=2)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_2",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_2",
						CMSSSignature.SWIFFTX384andWinternitzOTS_2.OID });

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_3",
						CMSSSignature.SWIFFTX384andWinternitzOTS_3.OID });

		// CMSS2 with SWIFFTX384 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX384andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX384andWinternitzOTS_4",
						CMSSSignature.SWIFFTX384andWinternitzOTS_4.OID });

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=1)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_1",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_1.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_1",
						CMSSSignature.SWIFFTX512andWinternitzOTS_1.OID });

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=2)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_2",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_2.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_2",
						CMSSSignature.SWIFFTX512andWinternitzOTS_2.OID });

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=3)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_3",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_3.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_3",
						CMSSSignature.SWIFFTX512andWinternitzOTS_3.OID });

		// CMSS2 with SWIFFTX512 and Winternitz OTS (w=4)
		add(KEY_PAIR_GENERATOR,
				CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_4",
						CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX512andWinternitzOTS_4.class,
				new String[] { "CMSS2withSWIFFTX512andWinternitzOTS_4",
						CMSSSignature.SWIFFTX512andWinternitzOTS_4.OID });

		// CMSS2 with SHA1 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SHA1andLMOTS.class,
				new String[] { "CMSS2withSHA1andLMOTS",
						CMSSKeyPairGenerator.SHA1andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SHA1andLMOTS.class, new String[] {
				"CMSS2withSHA1andLMOTS", CMSSSignature.SHA1andLMOTS.OID });

		// CMSS2 with SHA256 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SHA256andLMOTS.class,
				new String[] { "CMSS2withSHA256andLMOTS",
						CMSSKeyPairGenerator.SHA256andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SHA256andLMOTS.class, new String[] {
				"CMSS2withSHA256andLMOTS", CMSSSignature.SHA256andLMOTS.OID });

		// CMSS2 with SHA384 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SHA384andLMOTS.class,
				new String[] { "CMSS2withSHA384andLMOTS",
						CMSSKeyPairGenerator.SHA384andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SHA384andLMOTS.class, new String[] {
				"CMSS2withSHA384andLMOTS", CMSSSignature.SHA384andLMOTS.OID });

		// CMSS2 with SHA512 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SHA512andLMOTS.class,
				new String[] { "CMSS2withSHA512andLMOTS",
						CMSSKeyPairGenerator.SHA512andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SHA512andLMOTS.class, new String[] {
				"CMSS2withSHA512andLMOTS", CMSSSignature.SHA512andLMOTS.OID });

		// CMSS2 with SWIFFTX224 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SWIFFTX224andLMOTS.class,
				new String[] { "CMSS2withSWIFFTX224andLMOTS",
						CMSSKeyPairGenerator.SWIFFTX224andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX224andLMOTS.class, new String[] {
				"CMSS2withSWIFFTX224andLMOTS",
				CMSSSignature.SWIFFTX224andLMOTS.OID });

		// CMSS2 with SWIFFTX256 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SWIFFTX256andLMOTS.class,
				new String[] { "CMSS2withSWIFFTX256andLMOTS",
						CMSSKeyPairGenerator.SWIFFTX256andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX256andLMOTS.class, new String[] {
				"CMSS2withSWIFFTX256andLMOTS",
				CMSSSignature.SWIFFTX256andLMOTS.OID });

		// CMSS2 with SWIFFTX384 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SWIFFTX384andLMOTS.class,
				new String[] { "CMSS2withSWIFFTX384andLMOTS",
						CMSSKeyPairGenerator.SWIFFTX384andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX384andLMOTS.class, new String[] {
				"CMSS2withSWIFFTX384andLMOTS",
				CMSSSignature.SWIFFTX384andLMOTS.OID });

		// CMSS2 with SWIFFTX512 and LM OTS
		add(KEY_PAIR_GENERATOR, CMSSKeyPairGenerator.SWIFFTX512andLMOTS.class,
				new String[] { "CMSS2withSWIFFTX512andLMOTS",
						CMSSKeyPairGenerator.SWIFFTX512andLMOTS.OID });
		add(SIGNATURE, CMSSSignature.SWIFFTX512andLMOTS.class, new String[] {
				"CMSS2withSWIFFTX512andLMOTS",
				CMSSSignature.SWIFFTX512andLMOTS.OID });

	}

	private static void registerGMSS() {
		add(ALG_PARAM_SPEC, GMSSParameterSpec.class, new String[] { "GMSS",
				GMSSKeyFactory.OID });
		add(KEY_FACTORY, GMSSKeyFactory.class, new String[] { "GMSS",
				GMSSKeyFactory.OID });

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA1.class,
				new String[] { "GMSSwithSHA1",
						GMSSKeyPairGenerator.GMSSwithSHA1.OID });
		add(SIGNATURE, GMSSSignature.GMSSwithSHA1.class, new String[] {
				"GMSSwithSHA1", GMSSKeyPairGenerator.GMSSwithSHA1.OID });

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA224.class,
				new String[] { "GMSSwithSHA224",
						GMSSKeyPairGenerator.GMSSwithSHA224.OID });
		add(SIGNATURE, GMSSSignature.GMSSwithSHA224.class, new String[] {
				"GMSSwithSHA224", GMSSKeyPairGenerator.GMSSwithSHA224.OID });

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA256.class,
				new String[] { "GMSSwithSHA256",
						GMSSKeyPairGenerator.GMSSwithSHA256.OID });
		add(SIGNATURE, GMSSSignature.GMSSwithSHA256.class, new String[] {
				"GMSSwithSHA256", GMSSKeyPairGenerator.GMSSwithSHA256.OID });

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA384.class,
				new String[] { "GMSSwithSHA384",
						GMSSKeyPairGenerator.GMSSwithSHA384.OID });
		add(SIGNATURE, GMSSSignature.GMSSwithSHA384.class, new String[] {
				"GMSSwithSHA384", GMSSKeyPairGenerator.GMSSwithSHA384.OID });

		add(KEY_PAIR_GENERATOR, GMSSKeyPairGenerator.GMSSwithSHA512.class,
				new String[] { "GMSSwithSHA512",
						GMSSKeyPairGenerator.GMSSwithSHA512.OID });
		add(SIGNATURE, GMSSSignature.GMSSwithSHA512.class, new String[] {
				"GMSSwithSHA512", GMSSKeyPairGenerator.GMSSwithSHA512.OID });
	}

	private static void registerMcEliece() {
		// generic
		add(ALG_PARAM_SPEC, ECCKeyGenParameterSpec.class, new String[] {
				"McElieceKeyGen", "McElieceCCA2KeyGen", "NiederreiterKeyGen" });

		// McEliece PKCS
		add(KEY_PAIR_GENERATOR, McElieceKeyPairGenerator.class, new String[] {
				"McEliece", McElieceKeyFactory.OID });
		add(KEY_FACTORY, McElieceKeyFactory.class, new String[] { "McEliece",
				McElieceKeyFactory.OID });

		add(ASYMMETRIC_BLOCK_CIPHER, McEliecePKCS.class, new String[] {
				"McEliece", "McEliecePKCS", McEliecePKCS.OID });

		// CCA2 conversions
		add(KEY_PAIR_GENERATOR, McElieceCCA2KeyPairGenerator.class,
				new String[] { "McElieceCCA2", McElieceCCA2KeyFactory.OID });
		add(KEY_FACTORY, McElieceCCA2KeyFactory.class, new String[] {
				"McElieceCCA2", McElieceCCA2KeyFactory.OID });

		add(ALG_PARAM_SPEC, McElieceCCA2ParameterSpec.class, new String[] {
				"McElieceCCA2", "McElieceFujisakiCipher",
				McElieceFujisakiCipher.OID, "McEliecePointchevalCipher",
				McEliecePointchevalCipher.OID, "McElieceKobaraImaiCipher",
				McElieceKobaraImaiCipher.OID });

		add(ASYMMETRIC_HYBRID_CIPHER, McElieceFujisakiCipher.class,
				new String[] { "McElieceFujisakiCipher",
						McElieceFujisakiCipher.OID });
		add(ASYMMETRIC_HYBRID_CIPHER, McEliecePointchevalCipher.class,
				new String[] { "McEliecePointchevalCipher",
						McEliecePointchevalCipher.OID });
		add(ASYMMETRIC_HYBRID_CIPHER, McElieceKobaraImaiCipher.class,
				new String[] { "McElieceKobaraImaiCipher",
						McElieceKobaraImaiCipher.OID });
	}

	private static void registerNiederreiter() {
		// generic
		add(KEY_PAIR_GENERATOR, NiederreiterKeyPairGenerator.class,
				new String[] { "Niederreiter", NiederreiterKeyFactory.OID });
		add(KEY_FACTORY, NiederreiterKeyFactory.class, new String[] {
				"Niederreiter", NiederreiterKeyFactory.OID });
		add(ALG_PARAM_SPEC, ECCKeyGenParameterSpec.class, new String[] {
				"Niederreiter", "NiederreiterPKCS", NiederreiterPKCS.OID,
				"NiederreiterCFS", NiederreiterCFSSignature.OID });

		// Niederreiter PKCS
		add(ASYMMETRIC_BLOCK_CIPHER, NiederreiterPKCS.class, new String[] {
				"Niederreiter", "NiederreiterPKCS", NiederreiterPKCS.OID });

		// Niederreiter CFS signature
		add(SIGNATURE, NiederreiterCFSSignature.class,
				new String[] { "Niederreiter", "NiederreiterCFS",
						NiederreiterCFSSignature.OID });
	}



	private static void registerLMOTS() {
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
	 private static void registerRainbow() {
		add(KEY_PAIR_GENERATOR, RainbowKeyPairGenerator.class, "Rainbow");
		add(KEY_FACTORY, RainbowKeyFactory.class, "Rainbow");

		add(SIGNATURE, RainbowSignature.class, "Rainbow");
	    }
	private static void registerPflash() {
		add(KEY_PAIR_GENERATOR, PFlashKeyPairGenerator.class, "PFlash");
		add(KEY_FACTORY, PFlashKeyFactory.class, "PFlash");

		add(SIGNATURE, PFlashSignature.class, "PFlash");
	    }
	

}
