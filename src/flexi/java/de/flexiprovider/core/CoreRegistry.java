package de.flexiprovider.core;

import de.flexiprovider.api.Registry;
import de.flexiprovider.core.camellia.Camellia;
import de.flexiprovider.core.camellia.Camellia.Camellia128_CBC;
import de.flexiprovider.core.camellia.Camellia.Camellia192_CBC;
import de.flexiprovider.core.camellia.Camellia.Camellia256_CBC;
import de.flexiprovider.core.camellia.CamelliaKeyFactory;
import de.flexiprovider.core.camellia.CamelliaKeyGenParameterSpec;
import de.flexiprovider.core.camellia.CamelliaKeyGenerator;
import de.flexiprovider.core.desede.DESede;
import de.flexiprovider.core.desede.DESede.DESede_CBC;
import de.flexiprovider.core.desede.DESedeKeyFactory;
import de.flexiprovider.core.desede.DESedeKeyGenerator;
import de.flexiprovider.core.dsa.DSAKeyFactory;
import de.flexiprovider.core.dsa.DSAKeyPairGenerator;
import de.flexiprovider.core.dsa.DSAParamGenParameterSpec;
import de.flexiprovider.core.dsa.DSAParameterGenerator;
import de.flexiprovider.core.dsa.DSAParameterSpec;
import de.flexiprovider.core.dsa.DSAParameters;
import de.flexiprovider.core.dsa.DSASignature;
import de.flexiprovider.core.elgamal.ElGamal;
import de.flexiprovider.core.elgamal.ElGamalKeyFactory;
import de.flexiprovider.core.elgamal.ElGamalKeyGenParameterSpec;
import de.flexiprovider.core.elgamal.ElGamalKeyPairGenerator;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamal;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamalKeyFactory;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamalKeyGenParameterSpec;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamalKeyPairGenerator;
import de.flexiprovider.core.idea.IDEA;
import de.flexiprovider.core.idea.IDEA.IDEA_CBC;
import de.flexiprovider.core.idea.IDEA.IDEA_CFB;
import de.flexiprovider.core.idea.IDEA.IDEA_ECB;
import de.flexiprovider.core.idea.IDEA.IDEA_OFB;
import de.flexiprovider.core.idea.IDEAKeyFactory;
import de.flexiprovider.core.idea.IDEAKeyGenerator;
import de.flexiprovider.core.kdf.KDF1;
import de.flexiprovider.core.kdf.KDF2;
import de.flexiprovider.core.kdf.KDFParameterSpec;
import de.flexiprovider.core.kdf.PBKDF1;
import de.flexiprovider.core.kdf.PBKDF1_PKCS12;
import de.flexiprovider.core.kdf.PBKDF1_PKCS12ParameterSpec;
import de.flexiprovider.core.kdf.PBKDF2;
import de.flexiprovider.core.kdf.PBKDF2ParameterSpec;
import de.flexiprovider.core.kdf.PBKDF2Parameters;
import de.flexiprovider.core.kdf.X963;
import de.flexiprovider.core.mac.CBCMac;
import de.flexiprovider.core.mac.CMac;
import de.flexiprovider.core.mac.HMac;
import de.flexiprovider.core.mac.HMacKeyFactory;
import de.flexiprovider.core.mac.HMacKeyGenerator;
import de.flexiprovider.core.mac.TwoTrackMac;
import de.flexiprovider.core.mac.TwoTrackMacKeyFactory;
import de.flexiprovider.core.mac.TwoTrackMacKeyGenerator;
import de.flexiprovider.core.mars.MARS;
import de.flexiprovider.core.mars.MARSKeyFactory;
import de.flexiprovider.core.mars.MARSKeyGenParameterSpec;
import de.flexiprovider.core.mars.MARSKeyGenerator;
import de.flexiprovider.core.md.DHA256;
import de.flexiprovider.core.md.FORK256;
import de.flexiprovider.core.md.MD4;
import de.flexiprovider.core.md.MD5;
import de.flexiprovider.core.md.RIPEMD128;
import de.flexiprovider.core.md.RIPEMD160;
import de.flexiprovider.core.md.RIPEMD256;
import de.flexiprovider.core.md.RIPEMD320;
import de.flexiprovider.core.md.SHA1;
import de.flexiprovider.core.md.SHA224;
import de.flexiprovider.core.md.SHA256;
import de.flexiprovider.core.md.SHA384;
import de.flexiprovider.core.md.SHA512;
import de.flexiprovider.core.md.Tiger;
import de.flexiprovider.core.md.VSH;
import de.flexiprovider.core.md.swifftx.SWIFFTX224;
import de.flexiprovider.core.md.swifftx.SWIFFTX256;
import de.flexiprovider.core.md.swifftx.SWIFFTX384;
import de.flexiprovider.core.md.swifftx.SWIFFTX512;
import de.flexiprovider.core.mersa.MeRSA;
import de.flexiprovider.core.mersa.MeRSAKeyFactory;
import de.flexiprovider.core.mersa.MeRSAKeyGenParameterSpec;
import de.flexiprovider.core.mersa.MeRSAKeyPairGenerator;
import de.flexiprovider.core.mersa.MeRSASignaturePSS;
import de.flexiprovider.core.misty1.Misty1;
import de.flexiprovider.core.misty1.Misty1KeyFactory;
import de.flexiprovider.core.misty1.Misty1KeyGenerator;
import de.flexiprovider.core.mprsa.MpRSA;
import de.flexiprovider.core.mprsa.MpRSAKeyGenParameterSpec;
import de.flexiprovider.core.mprsa.MpRSAKeyPairGenerator;
import de.flexiprovider.core.mprsa.MpRSASignaturePSS;
import de.flexiprovider.core.pbe.PBEKeyFactory;
import de.flexiprovider.core.pbe.PBEKeyGenParameterSpec;
import de.flexiprovider.core.pbe.PBEKeyGenerator;
import de.flexiprovider.core.pbe.PBEParameterSpec;
import de.flexiprovider.core.pbe.PBEParameters;
import de.flexiprovider.core.pbe.PBES2;
import de.flexiprovider.core.pbe.PBES2ParameterSpec;
import de.flexiprovider.core.pbe.PBES2Parameters;
import de.flexiprovider.core.pbe.PBEWithMD5AndDES_CBC;
import de.flexiprovider.core.pbe.PBEWithSHA1AndDES_CBC;
import de.flexiprovider.core.pbe.PBEWithSHAAnd3_KeyTripleDES_CBC;
import de.flexiprovider.core.pbe.PBEWithSHAAnd40BitRC2_CBC;
import de.flexiprovider.core.random.BBSRandom;
import de.flexiprovider.core.random.SHA1PRNG;
import de.flexiprovider.core.rbrsa.RbRSAKeyGenParameterSpec;
import de.flexiprovider.core.rbrsa.RbRSAKeyPairGenerator;
import de.flexiprovider.core.rc2.RC2;
import de.flexiprovider.core.rc2.RC2.RC2_CBC;
import de.flexiprovider.core.rc2.RC2KeyFactory;
import de.flexiprovider.core.rc2.RC2KeyGenParameterSpec;
import de.flexiprovider.core.rc2.RC2KeyGenerator;
import de.flexiprovider.core.rc5.RC5;
import de.flexiprovider.core.rc5.RC5KeyFactory;
import de.flexiprovider.core.rc5.RC5KeyGenParameterSpec;
import de.flexiprovider.core.rc5.RC5KeyGenerator;
import de.flexiprovider.core.rc5.RC5ParameterSpec;
import de.flexiprovider.core.rc5.RC5Parameters;
import de.flexiprovider.core.rc6.RC6;
import de.flexiprovider.core.rc6.RC6KeyFactory;
import de.flexiprovider.core.rc6.RC6KeyGenParameterSpec;
import de.flexiprovider.core.rc6.RC6KeyGenerator;
import de.flexiprovider.core.rijndael.Rijndael;
import de.flexiprovider.core.rijndael.Rijndael.AES;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES128_CBC;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES128_CFB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES128_ECB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES128_OFB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES192_CBC;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES192_CFB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES192_ECB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES192_OFB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES256_CBC;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES256_CFB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES256_ECB;
import de.flexiprovider.core.rijndael.Rijndael.AES.AES256_OFB;
import de.flexiprovider.core.rijndael.RijndaelKeyFactory;
import de.flexiprovider.core.rijndael.RijndaelKeyGenParameterSpec;
import de.flexiprovider.core.rijndael.RijndaelKeyGenerator;
import de.flexiprovider.core.rijndael.RijndaelParameterSpec;
import de.flexiprovider.core.rijndael.RijndaelParameters;
import de.flexiprovider.core.rprimersa.RprimeRSAKeyGenParameterSpec;
import de.flexiprovider.core.rprimersa.RprimeRSAKeyPairGenerator;
import de.flexiprovider.core.rsa.PSSParameterSpec;
import de.flexiprovider.core.rsa.PSSParameters;
import de.flexiprovider.core.rsa.RSAKeyFactory;
import de.flexiprovider.core.rsa.RSAKeyGenParameterSpec;
import de.flexiprovider.core.rsa.RSAKeyPairGenerator;
import de.flexiprovider.core.rsa.RSAOAEPParameterSpec;
import de.flexiprovider.core.rsa.RSAOAEPParameters;
import de.flexiprovider.core.rsa.RSASignaturePKCS1v15;
import de.flexiprovider.core.rsa.RSASignaturePSS;
import de.flexiprovider.core.rsa.RSA_PKCS1_v1_5;
import de.flexiprovider.core.rsa.RSA_PKCS1_v2_1;
import de.flexiprovider.core.rsa.SSLSignature;
import de.flexiprovider.core.rsa.UnlimitedLengthRSA;
import de.flexiprovider.core.saferplus.SAFERPlus;
import de.flexiprovider.core.saferplus.SAFERPlusKeyFactory;
import de.flexiprovider.core.saferplus.SAFERPlusKeyGenParameterSpec;
import de.flexiprovider.core.saferplus.SAFERPlusKeyGenerator;
import de.flexiprovider.core.saferplusplus.SAFERPlusPlus;
import de.flexiprovider.core.saferplusplus.SAFERPlusPlusKeyFactory;
import de.flexiprovider.core.saferplusplus.SAFERPlusPlusKeyGenParameterSpec;
import de.flexiprovider.core.saferplusplus.SAFERPlusPlusKeyGenerator;
import de.flexiprovider.core.serpent.Serpent;
import de.flexiprovider.core.serpent.Serpent.Serpent128_CBC;
import de.flexiprovider.core.serpent.Serpent.Serpent128_CFB;
import de.flexiprovider.core.serpent.Serpent.Serpent128_ECB;
import de.flexiprovider.core.serpent.Serpent.Serpent128_OFB;
import de.flexiprovider.core.serpent.Serpent.Serpent192_CBC;
import de.flexiprovider.core.serpent.Serpent.Serpent192_CFB;
import de.flexiprovider.core.serpent.Serpent.Serpent192_ECB;
import de.flexiprovider.core.serpent.Serpent.Serpent192_OFB;
import de.flexiprovider.core.serpent.Serpent.Serpent256_CBC;
import de.flexiprovider.core.serpent.Serpent.Serpent256_CFB;
import de.flexiprovider.core.serpent.Serpent.Serpent256_ECB;
import de.flexiprovider.core.serpent.Serpent.Serpent256_OFB;
import de.flexiprovider.core.serpent.SerpentKeyFactory;
import de.flexiprovider.core.serpent.SerpentKeyGenParameterSpec;
import de.flexiprovider.core.serpent.SerpentKeyGenerator;
import de.flexiprovider.core.shacal.Shacal;
import de.flexiprovider.core.shacal.ShacalKeyFactory;
import de.flexiprovider.core.shacal.ShacalKeyGenParameterSpec;
import de.flexiprovider.core.shacal.ShacalKeyGenerator;
import de.flexiprovider.core.shacal2.Shacal2;
import de.flexiprovider.core.shacal2.Shacal2KeyFactory;
import de.flexiprovider.core.shacal2.Shacal2KeyGenParameterSpec;
import de.flexiprovider.core.shacal2.Shacal2KeyGenerator;
import de.flexiprovider.core.twofish.Twofish;
import de.flexiprovider.core.twofish.TwofishKeyFactory;
import de.flexiprovider.core.twofish.TwofishKeyGenParameterSpec;
import de.flexiprovider.core.twofish.TwofishKeyGenerator;

/**
 * Register all algorithms of the <a href="package.html">core package</a>.
 */
public abstract class CoreRegistry extends Registry {

	// flag indicating if algorithms already have been registered
	private static boolean registered = false;

	/**
	 * Register all algorithms of the <a href="package.html">core package</a>.
	 */
	public static void registerAlgorithms() {
		if (!registered) {
			registerDSA();
			registerRSA();
			registerElGamal();
			registerSSVElGamal();
			registerSHAfamily();
			registerMDfamily();
			registerRIPEMDfamily();
			registerTiger();
			registerDHA256();
			registerFORK256();
			registerSWIFFTX();
			registerVSH();
			registerHMAC();
			registerCBCMAC();
			registerTTMAC();
			registerCMAC();
			registerAESRijndael();
			registerCamellia();
			registerDESede();
			registerIDEA();
			registerMARS();
			registerMisty1();
			registerRC2();
			registerRC5();
			registerRC6();
			registerSAFERPlus();
			registerSAFERPlusPlus();
			registerSerpent();
			registerShacal();
			registerShacal2();
			registerTwofish();
			registerPBE();
			registerKDF();
			registerBBS();
			registerSHA1PRNG();
			registered = true;
		}
	}

	private static void registerDSA() {
		add(ALG_PARAM_SPEC, DSAParamGenParameterSpec.class, new String[] {
				"DSAParamGen", DSAParameterGenerator.OID,
				DSAParameterGenerator.OID2 });
		add(ALG_PARAM_GENERATOR, DSAParameterGenerator.class, new String[] {
				"DSA", DSAParameterGenerator.OID, DSAParameterGenerator.OID2 });

		add(ALG_PARAM_SPEC, DSAParameterSpec.class, new String[] {
				"SHA1withDSA", "SHA1/DSA", "SHAwithDSA", "SHA/DSA", "DSS",
				DSAParameters.OID, DSAParameters.OID2, DSASignature.SHA1.OID,
				DSASignature.SHA1.OID2, DSASignature.SHA1.OID3 });
		add(ALG_PARAMS, DSAParameters.class, new String[] { "DSA",
				DSAParameters.OID, DSAParameters.OID2 });

		add(KEY_PAIR_GENERATOR, DSAKeyPairGenerator.class, new String[] {
				"DSA", DSAKeyFactory.OID, DSAKeyFactory.OID2 });
		add(KEY_FACTORY, DSAKeyFactory.class, new String[] { "DSA",
				DSAKeyFactory.OID, DSAKeyFactory.OID2 });

		// DSA signature with SHA1
		add(SIGNATURE, DSASignature.SHA1.class, new String[] { "SHA1withDSA",
				"SHA1/DSA", "SHAwithDSA", "SHA/DSA", "DSS",
				DSASignature.SHA1.OID, DSASignature.SHA1.OID2,
				DSASignature.SHA1.OID3 });

		// DSA signature with SHA224
		add(SIGNATURE, DSASignature.SHA224.class, new String[] {
				"SHA224withDSA", "SHA224/DSA" });

		// DSA signature with SHA256
		add(SIGNATURE, DSASignature.SHA256.class, new String[] {
				"SHA256withDSA", "SHA256/DSA" });

		// DSA signature with SHA384
		add(SIGNATURE, DSASignature.SHA384.class, new String[] {
				"SHA384withDSA", "SHA384/DSA" });

		// DSA signature with SHA512
		add(SIGNATURE, DSASignature.SHA512.class, new String[] {
				"SHA512withDSA", "SHA512/DSA" });

		// DSA signature with precomputed hash
		add(SIGNATURE, DSASignature.Raw.class, new String[] { "RawDSA",
				"RAW/DSA" });
	}

	private static void registerRSA() {
		// generic
		add(ALG_PARAM_SPEC, RSAKeyGenParameterSpec.class, new String[] {
				"RSAKeyGen", RSAKeyFactory.OID });
		add(KEY_PAIR_GENERATOR, RSAKeyPairGenerator.class, new String[] {
				"RSA", RSAKeyFactory.OID });
		add(KEY_FACTORY, RSAKeyFactory.class, new String[] { "RSA", "MpRSA",
				"RbRSA", "RprimeRSA", RSAKeyFactory.OID });

		// ---------------------------------------------------------

		// RSA cipher according to PKCS #1 v1.5
		Registry.add(ASYMMETRIC_BLOCK_CIPHER, RSA_PKCS1_v1_5.class,
				new String[] { "RSA", "RSA_PKCS1_v1_5", RSA_PKCS1_v1_5.OID });

		// RSA Cipher with unlimited length (in ECB mode)
		Registry.add(ASYMMETRIC_BLOCK_CIPHER, UnlimitedLengthRSA.class,
				new String[] { UnlimitedLengthRSA.NAME });

		// ---------------------------------------------------------

		// RSA cipher according to PKCS #1 v2.1 (RSA-OAEP)
		add(ALG_PARAM_SPEC, RSAOAEPParameterSpec.class, new String[] {
				"RSA_PKCS1_v2_1", "RSA-OAEP", RSA_PKCS1_v2_1.OID });
		add(ALG_PARAMS, RSAOAEPParameters.class, new String[] {
				"RSA_PKCS1_v2_1", "RSA-OAEP", RSA_PKCS1_v2_1.OID });

		add(ASYMMETRIC_BLOCK_CIPHER, RSA_PKCS1_v2_1.class, new String[] {
				"RSA_PKCS1_v2_1", "RSA-OAEP", RSA_PKCS1_v2_1.OID });

		// ---------------------------------------------------------

		/*
		 * RSA-SSA signature according to PKCS #1 v1.5
		 */

		// RSA-SSA signature with MD5
		add(SIGNATURE, RSASignaturePKCS1v15.MD5.class, new String[] {
				"MD5withRSA", "MD5/RSA", RSASignaturePKCS1v15.MD5.OID,
				RSASignaturePKCS1v15.MD5.ALTERNATIVE_OID });

		// RSA-SSA signature with SHA1
		add(SIGNATURE, RSASignaturePKCS1v15.SHA1.class, new String[] {
				"SHA1withRSA", "SHAwithRSA", "SHA1/RSA", "SHA/RSA",
				RSASignaturePKCS1v15.SHA1.OID,
				RSASignaturePKCS1v15.SHA1.ALTERNATIVE_OID });

		// RSA-SSA signature with SHA224
		add(SIGNATURE, RSASignaturePKCS1v15.SHA224.class,
				new String[] { "SHA224withRSA", "SHA224/RSA",
						RSASignaturePKCS1v15.SHA224.OID });

		// RSA-SSA signature with SHA256
		add(SIGNATURE, RSASignaturePKCS1v15.SHA256.class,
				new String[] { "SHA256withRSA", "SHA256/RSA",
						RSASignaturePKCS1v15.SHA256.OID });

		// RSA-SSA signature with SHA384
		add(SIGNATURE, RSASignaturePKCS1v15.SHA384.class,
				new String[] { "SHA384withRSA", "SHA384/RSA",
						RSASignaturePKCS1v15.SHA384.OID });

		// RSA-SSA signature with SHA512
		add(SIGNATURE, RSASignaturePKCS1v15.SHA512.class,
				new String[] { "SHA512withRSA", "SHA512/RSA",
						RSASignaturePKCS1v15.SHA512.OID });

		// RSA-SSA signature with RIPEMD160
		add(SIGNATURE, RSASignaturePKCS1v15.RIPEMD160.class, new String[] {
				"RIPEMD160withRSA", "RIPEMD160/RSA",
				RSASignaturePKCS1v15.RIPEMD160.OID });

		// ---------------------------------------------------------

		// RSA-SSA signatures according to PKCS #1 v1.5 with precomputed hashes.
		// We need to have distinct registrations even in this case since the
		// OID of the message digest is embedded into the signature.
		add(SIGNATURE, RSASignaturePKCS1v15.RawMD5.class, "MD5/RSA/RAW");
		add(SIGNATURE, RSASignaturePKCS1v15.RawSHA1.class, "SHA1/RSA/RAW");
		add(SIGNATURE, RSASignaturePKCS1v15.RawSHA224.class, "SHA224/RSA/RAW");
		add(SIGNATURE, RSASignaturePKCS1v15.RawSHA256.class, "SHA256/RSA/RAW");
		add(SIGNATURE, RSASignaturePKCS1v15.RawSHA384.class, "SHA384/RSA/RAW");
		add(SIGNATURE, RSASignaturePKCS1v15.RawSHA512.class, "SHA512/RSA/RAW");
		add(SIGNATURE, RSASignaturePKCS1v15.RawRIPEMD160.class,
				"RIPEMD160/RSA/RAW");

		// ---------------------------------------------------------

		// RSA-SSA PSS signature according to PKCS #1 v2.1
		add(ALG_PARAM_SPEC, PSSParameterSpec.class, new String[] {
				"RSASSA-PSS", RSASignaturePSS.OID });
		add(ALG_PARAMS, PSSParameters.class, new String[] { "RSASSA-PSS",
				RSASignaturePSS.OID });

		add(SIGNATURE, RSASignaturePSS.class, new String[] { "RSASSA-PSS",
				RSASignaturePSS.OID });

		// ---------------------------------------------------------

		// SSL Signature (MD5+SHA1 hash without DigestInfo)
		add(SIGNATURE, SSLSignature.class, "SSL_MD5andSHA1withRSA");

		// ---------------------------------------------------------

		// multi-exponent RSA
		add(ALG_PARAM_SPEC, MeRSAKeyGenParameterSpec.class, "MeRSAKeyGen");
		add(KEY_PAIR_GENERATOR, MeRSAKeyPairGenerator.class, "MeRSA");
		add(KEY_FACTORY, MeRSAKeyFactory.class, "MeRSA");

		add(ASYMMETRIC_BLOCK_CIPHER, MeRSA.class, "MeRSA");
		add(SIGNATURE, MeRSASignaturePSS.class, "MeRSA");

		// ---------------------------------------------------------

		// multi-prime RSA
		add(ALG_PARAM_SPEC, MpRSAKeyGenParameterSpec.class, "MpRSAKeyGen");
		add(KEY_PAIR_GENERATOR, MpRSAKeyPairGenerator.class, "MpRSA");
		// key factory is same as for standard RSA (registered above)

		add(ASYMMETRIC_BLOCK_CIPHER, MpRSA.class, "MpRSA");
		add(SIGNATURE, MpRSASignaturePSS.class, "MpRSA");

		// ---------------------------------------------------------

		// rebalanced RSA
		add(ALG_PARAM_SPEC, RbRSAKeyGenParameterSpec.class, "RbRSAKeyGen");
		add(KEY_PAIR_GENERATOR, RbRSAKeyPairGenerator.class, "RbRSA");
		// key factory is same as for standard RSA (registered above)

		add(ASYMMETRIC_BLOCK_CIPHER, RSA_PKCS1_v2_1.class, "RbRSA");
		add(SIGNATURE, RSASignaturePSS.class, "RbRSA");

		// ---------------------------------------------------------

		// Rprime RSA (Rebalanced multi-prime RSA)
		add(ALG_PARAM_SPEC, RprimeRSAKeyGenParameterSpec.class,
				"RprimeRSAKeyGen");
		add(KEY_PAIR_GENERATOR, RprimeRSAKeyPairGenerator.class, "RprimeRSA");
		// key factory is same as for standard RSA (registered above)

		Registry.add(ASYMMETRIC_BLOCK_CIPHER, MpRSA.class, "RprimeRSA");
		add(SIGNATURE, MpRSASignaturePSS.class, "RprimeRSA");
	}

	private static void registerElGamal() {
		add(ALG_PARAM_SPEC, ElGamalKeyGenParameterSpec.class, new String[] {
				ElGamal.ALG_NAME + "KeyGen", ElGamalKeyPairGenerator.OID });
		add(KEY_PAIR_GENERATOR, ElGamalKeyPairGenerator.class, new String[] {
				ElGamal.ALG_NAME, ElGamalKeyPairGenerator.OID });
		add(KEY_FACTORY, ElGamalKeyFactory.class, new String[] {
				ElGamal.ALG_NAME, ElGamalKeyFactory.OID });

		add(ASYMMETRIC_BLOCK_CIPHER, ElGamal.class, new String[] {
				ElGamal.ALG_NAME, ElGamal.OID });
	}

	private static void registerSSVElGamal() {
		add(ALG_PARAM_SPEC, SSVElGamalKeyGenParameterSpec.class,
				SSVElGamal.ALG_NAME + "KeyGen");
		add(KEY_PAIR_GENERATOR, SSVElGamalKeyPairGenerator.class,
				SSVElGamal.ALG_NAME);
		add(KEY_FACTORY, SSVElGamalKeyFactory.class, SSVElGamal.ALG_NAME);

		add(ASYMMETRIC_BLOCK_CIPHER, SSVElGamal.class, SSVElGamal.ALG_NAME);
	}

	private static void registerSHAfamily() {
		add(MESSAGE_DIGEST, SHA1.class, new String[] { SHA1.ALG_NAME,
				SHA1.ALG_NAME2, SHA1.OID });
		add(MESSAGE_DIGEST, SHA224.class, new String[] { SHA224.ALG_NAME,
				SHA224.OID });
		add(MESSAGE_DIGEST, SHA256.class, new String[] { SHA256.ALG_NAME,
				SHA256.OID });
		add(MESSAGE_DIGEST, SHA384.class, new String[] { SHA384.ALG_NAME,
				SHA384.OID });
		add(MESSAGE_DIGEST, SHA512.class, new String[] { SHA512.ALG_NAME,
				SHA512.OID });
	}

	private static void registerMDfamily() {
		add(MESSAGE_DIGEST, MD4.class, new String[] { MD4.ALG_NAME, MD4.OID });
		add(MESSAGE_DIGEST, MD5.class, new String[] { MD5.ALG_NAME, MD5.OID });
	}

	private static void registerRIPEMDfamily() {
		add(MESSAGE_DIGEST, RIPEMD128.class, new String[] { RIPEMD128.ALG_NAME,
				RIPEMD128.OID });
		add(MESSAGE_DIGEST, RIPEMD160.class, new String[] { RIPEMD160.ALG_NAME,
				RIPEMD160.OID });
		add(MESSAGE_DIGEST, RIPEMD256.class, new String[] { RIPEMD256.ALG_NAME,
				RIPEMD256.OID });
		add(MESSAGE_DIGEST, RIPEMD320.class, RIPEMD320.ALG_NAME);
	}

	private static void registerTiger() {
		add(MESSAGE_DIGEST, Tiger.class, new String[] { Tiger.ALG_NAME,
				Tiger.OID });
	}

	private static void registerDHA256() {
		add(MESSAGE_DIGEST, DHA256.class, DHA256.ALG_NAME);
	}

	private static void registerFORK256() {
		add(MESSAGE_DIGEST, FORK256.class, FORK256.ALG_NAME);
	}

	private static void registerSWIFFTX() {
		add(MESSAGE_DIGEST, SWIFFTX224.class, SWIFFTX224.ALG_NAME);
		add(MESSAGE_DIGEST, SWIFFTX256.class, SWIFFTX256.ALG_NAME);
		add(MESSAGE_DIGEST, SWIFFTX384.class, SWIFFTX384.ALG_NAME);
		add(MESSAGE_DIGEST, SWIFFTX512.class, SWIFFTX512.ALG_NAME);
	}

	private static void registerVSH() {
		add(MESSAGE_DIGEST, VSH.class, VSH.ALG_NAME);
	}

	private static void registerCBCMAC() {
		add(MAC, CBCMac.AES128.class, CBCMac.AES128.ALG_NAME);
		add(MAC, CBCMac.AES192.class, CBCMac.AES192.ALG_NAME);
		add(MAC, CBCMac.AES256.class, CBCMac.AES256.ALG_NAME);
		add(MAC, CBCMac.Camellia.class, CBCMac.Camellia.ALG_NAME);
		add(MAC, CBCMac.DESede.class, CBCMac.DESede.ALG_NAME);
		add(MAC, CBCMac.IDEA.class, CBCMac.IDEA.ALG_NAME);
		add(MAC, CBCMac.MARS.class, CBCMac.MARS.ALG_NAME);
		add(MAC, CBCMac.Misty1.class, CBCMac.Misty1.ALG_NAME);
		add(MAC, CBCMac.RC2.class, CBCMac.RC2.ALG_NAME);
		add(MAC, CBCMac.RC5.class, CBCMac.RC5.ALG_NAME);
		add(MAC, CBCMac.RC6.class, CBCMac.RC6.ALG_NAME);
		add(MAC, CBCMac.SAFERPlus.class, CBCMac.SAFERPlus.ALG_NAME);
		add(MAC, CBCMac.SAFERPlusPlus.class, CBCMac.SAFERPlusPlus.ALG_NAME);
		add(MAC, CBCMac.Serpent.class, CBCMac.Serpent.ALG_NAME);
		add(MAC, CBCMac.Shacal.class, CBCMac.Shacal.ALG_NAME);
		add(MAC, CBCMac.Shacal2.class, CBCMac.Shacal2.ALG_NAME);
		add(MAC, CBCMac.Twofish.class, CBCMac.Twofish.ALG_NAME);
	}

	private static void registerCMAC() {
		add(MAC, CMac.DESede.class, CMac.DESede.ALG_NAME);
		add(MAC, CMac.AES128.class, CMac.AES128.ALG_NAME);
		add(MAC, CMac.AES192.class, CMac.AES192.ALG_NAME);
		add(MAC, CMac.AES256.class, CMac.AES256.ALG_NAME);
	}

	private static void registerHMAC() {
		// OIDs are defined by RFC 3370
		add(SECRET_KEY_FACTORY, HMacKeyFactory.class, new String[] { "Hmac",
				"HmacSHA1", HMac.SHA1.OID, HMac.SHA1.PKCS5_OID, "HmacSHA224",
				"HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacMD4", "HmacMD5",
				HMac.MD5.OID, "HmacRIPEMD128", "HmacRIPEMD160",
				HMac.RIPEMD160.OID, "HmacRIPEMD256", "HmacRIPEMD320",
				"HmacTiger", HMac.Tiger.OID, "HmacDHA256", "HmacFORK256", });

		// HmacSHA1
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.SHA1.class, new String[] {
				"Hmac", "HmacSHA1", HMac.SHA1.OID, HMac.SHA1.PKCS5_OID });
		add(MAC, HMac.SHA1.class, new String[] { "Hmac", "HmacSHA1",
				HMac.SHA1.OID });

		// HmacSHA224
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.SHA224.class, "HmacSHA224");
		add(MAC, HMac.SHA224.class, "HmacSHA224");

		// HmacSHA256
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.SHA256.class, "HmacSHA256");
		add(MAC, HMac.SHA256.class, "HmacSHA256");

		// HmacSHA384
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.SHA384.class, "HmacSHA384");
		add(MAC, HMac.SHA384.class, "HmacSHA384");

		// HmacSHA512
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.SHA512.class, "HmacSHA512");
		add(MAC, HMac.SHA512.class, "HmacSHA512");

		// HmacMD4
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.MD4.class, "HmacMD4");
		add(MAC, HMac.MD4.class, "HmacMD4");

		// HmacMD5
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.MD5.class, new String[] {
				"HmacMD5", HMac.MD5.OID });
		add(MAC, HMac.MD5.class, new String[] { "HmacMD5", HMac.MD5.OID });

		// HmacRIPEMD128
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.RIPEMD128.class,
				"HmacRIPEMD128");
		add(MAC, HMac.RIPEMD128.class, "HmacRIPEMD128");

		// HmacRIPEMD160
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.RIPEMD160.class,
				new String[] { "HmacRIPEMD160", HMac.RIPEMD160.OID });
		add(MAC, HMac.RIPEMD160.class, new String[] { "HmacRIPEMD160",
				HMac.RIPEMD160.OID });

		// HmacRIPEMD256
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.RIPEMD256.class,
				"HmacRIPEMD256");
		add(MAC, HMac.RIPEMD256.class, "HmacRIPEMD256");

		// HmacRIPEMD320
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.RIPEMD320.class,
				"HmacRIPEMD320");
		add(MAC, HMac.RIPEMD320.class, "HmacRIPEMD320");

		// HmacTiger
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.Tiger.class, new String[] {
				"HmacTiger", HMac.Tiger.OID });
		add(MAC, HMac.Tiger.class, new String[] { "HmacTiger", HMac.Tiger.OID });

		// HmacDHA256
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.DHA256.class, "HmacDHA256");
		add(MAC, HMac.DHA256.class, "HmacDHA256");

		// HmacFORK256
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.FORK256.class, "HmacFORK256");
		add(MAC, HMac.FORK256.class, "HmacFORK256");
	}

	private static void registerTTMAC() {
		add(SECRET_KEY_GENERATOR, TwoTrackMacKeyGenerator.class,
				new String[] { TwoTrackMac.TTMac32.ALG_NAME,
						TwoTrackMac.TTMac32.ALG_NAME2,
						TwoTrackMac.TTMac64.ALG_NAME,
						TwoTrackMac.TTMac64.ALG_NAME2,
						TwoTrackMac.TTMac96.ALG_NAME,
						TwoTrackMac.TTMac96.ALG_NAME2,
						TwoTrackMac.TTMac128.ALG_NAME,
						TwoTrackMac.TTMac128.ALG_NAME2,
						TwoTrackMac.TTMac160.ALG_NAME,
						TwoTrackMac.TTMac160.ALG_NAME2,
						TwoTrackMac.TTMac160.ALG_NAME3,
						TwoTrackMac.TTMac160.ALG_NAME4 });
		add(SECRET_KEY_FACTORY, TwoTrackMacKeyFactory.class,
				new String[] { TwoTrackMac.TTMac32.ALG_NAME,
						TwoTrackMac.TTMac32.ALG_NAME2,
						TwoTrackMac.TTMac64.ALG_NAME,
						TwoTrackMac.TTMac64.ALG_NAME2,
						TwoTrackMac.TTMac96.ALG_NAME,
						TwoTrackMac.TTMac96.ALG_NAME2,
						TwoTrackMac.TTMac128.ALG_NAME,
						TwoTrackMac.TTMac128.ALG_NAME2,
						TwoTrackMac.TTMac160.ALG_NAME,
						TwoTrackMac.TTMac160.ALG_NAME2,
						TwoTrackMac.TTMac160.ALG_NAME3,
						TwoTrackMac.TTMac160.ALG_NAME4 });

		// TwoTrackMac 32
		add(MAC, TwoTrackMac.TTMac32.class, new String[] {
				TwoTrackMac.TTMac32.ALG_NAME, TwoTrackMac.TTMac32.ALG_NAME2 });

		// TwoTrackMac 64
		add(MAC, TwoTrackMac.TTMac64.class, new String[] {
				TwoTrackMac.TTMac64.ALG_NAME, TwoTrackMac.TTMac64.ALG_NAME2 });

		// TwoTrackMac 96
		add(MAC, TwoTrackMac.TTMac96.class, new String[] {
				TwoTrackMac.TTMac96.ALG_NAME, TwoTrackMac.TTMac96.ALG_NAME2 });

		// TwoTrackMac 128
		add(MAC, TwoTrackMac.TTMac128.class, new String[] {
				TwoTrackMac.TTMac128.ALG_NAME, TwoTrackMac.TTMac128.ALG_NAME2 });

		// TwoTrackMac 160
		add(MAC, TwoTrackMac.TTMac160.class,
				new String[] { TwoTrackMac.TTMac160.ALG_NAME,
						TwoTrackMac.TTMac160.ALG_NAME2,
						TwoTrackMac.TTMac160.ALG_NAME3,
						TwoTrackMac.TTMac160.ALG_NAME4 });
	}

	private static void registerAESRijndael() {
		/* common */

		add(ALG_PARAM_SPEC, RijndaelKeyGenParameterSpec.class,
				new String[] { Rijndael.ALG_NAME + "KeyGen",
						AES.ALG_NAME + "KeyGen", AES.OID });
		add(SECRET_KEY_GENERATOR, RijndaelKeyGenerator.class, new String[] {
				Rijndael.ALG_NAME, AES.ALG_NAME, AES.OID });
		add(SECRET_KEY_FACTORY, RijndaelKeyFactory.class, new String[] {
				Rijndael.ALG_NAME, AES.ALG_NAME, AES.OID });

		/* AES */

		add(BLOCK_CIPHER, AES.class, new String[] { AES.ALG_NAME, AES.OID });

		add(BLOCK_CIPHER, AES128_ECB.class, new String[] { AES128_ECB.ALG_NAME,
				AES128_ECB.OID });
		add(BLOCK_CIPHER, AES128_CBC.class, new String[] { AES128_CBC.ALG_NAME,
				AES128_CBC.OID });
		add(BLOCK_CIPHER, AES128_OFB.class, new String[] { AES128_OFB.ALG_NAME,
				AES128_OFB.OID });
		add(BLOCK_CIPHER, AES128_CFB.class, new String[] { AES128_CFB.ALG_NAME,
				AES128_CFB.OID });

		add(BLOCK_CIPHER, AES192_ECB.class, new String[] { AES192_ECB.ALG_NAME,
				AES192_ECB.OID });
		add(BLOCK_CIPHER, AES192_CBC.class, new String[] { AES192_CBC.ALG_NAME,
				AES192_CBC.OID });
		add(BLOCK_CIPHER, AES192_OFB.class, new String[] { AES192_OFB.ALG_NAME,
				AES192_OFB.OID });
		add(BLOCK_CIPHER, AES192_CFB.class, new String[] { AES192_CFB.ALG_NAME,
				AES192_CFB.OID });

		add(BLOCK_CIPHER, AES256_ECB.class, new String[] { AES256_ECB.ALG_NAME,
				AES256_ECB.OID });
		add(BLOCK_CIPHER, AES256_CBC.class, new String[] { AES256_CBC.ALG_NAME,
				AES256_CBC.OID });
		add(BLOCK_CIPHER, AES256_OFB.class, new String[] { AES256_OFB.ALG_NAME,
				AES256_OFB.OID });
		add(BLOCK_CIPHER, AES256_CFB.class, new String[] { AES256_CFB.ALG_NAME,
				AES256_CFB.OID });

		/* Rijndael */

		add(ALG_PARAM_SPEC, RijndaelParameterSpec.class, Rijndael.ALG_NAME);
		add(ALG_PARAMS, RijndaelParameters.class, Rijndael.ALG_NAME);

		add(BLOCK_CIPHER, Rijndael.class, Rijndael.ALG_NAME);
	}

	private static void registerCamellia() {
		add(ALG_PARAM_SPEC, CamelliaKeyGenParameterSpec.class,
				Camellia.ALG_NAME + "KeyGen");
		add(SECRET_KEY_GENERATOR, CamelliaKeyGenerator.class, Camellia.ALG_NAME);
		add(SECRET_KEY_FACTORY, CamelliaKeyFactory.class, Camellia.ALG_NAME);

		add(BLOCK_CIPHER, Camellia.class, Camellia.ALG_NAME);
		Registry.add(BLOCK_CIPHER, Camellia128_CBC.class, new String[] {
				"Camellia128_CBC", Camellia128_CBC.OID });
		Registry.add(BLOCK_CIPHER, Camellia192_CBC.class, new String[] {
				"Camellia192_CBC", Camellia192_CBC.OID });
		Registry.add(BLOCK_CIPHER, Camellia256_CBC.class, new String[] {
				"Camellia256_CBC", Camellia256_CBC.OID });
	}

	private static void registerDESede() {
		add(SECRET_KEY_GENERATOR, DESedeKeyGenerator.class, new String[] {
				DESede.ALG_NAME, DESede_CBC.OID });
		add(SECRET_KEY_FACTORY, DESedeKeyFactory.class, new String[] {
				DESede.ALG_NAME, DESede_CBC.OID });

		add(BLOCK_CIPHER, DESede.class, DESede.ALG_NAME);
		add(BLOCK_CIPHER, DESede_CBC.class, new String[] { DESede_CBC.ALG_NAME,
				DESede_CBC.OID });
	}

	private static void registerIDEA() {
		add(SECRET_KEY_GENERATOR, IDEAKeyGenerator.class, new String[] {
				IDEA.ALG_NAME, IDEA.OID });
		add(SECRET_KEY_FACTORY, IDEAKeyFactory.class, new String[] {
				IDEA.ALG_NAME, IDEA.OID });

		add(BLOCK_CIPHER, IDEA.class, new String[] { IDEA.ALG_NAME, IDEA.OID });

		add(BLOCK_CIPHER, IDEA_ECB.class, new String[] { "IDEA_ECB",
				IDEA_ECB.OID });
		add(BLOCK_CIPHER, IDEA_CBC.class, new String[] { "IDEA_CBC",
				IDEA_CBC.OID });
		add(BLOCK_CIPHER, IDEA_CFB.class, new String[] { "IDEA_CFB",
				IDEA_CFB.OID });
		add(BLOCK_CIPHER, IDEA_OFB.class, new String[] { "IDEA_OFB",
				IDEA_OFB.OID });
	}

	private static void registerMARS() {
		add(ALG_PARAM_SPEC, MARSKeyGenParameterSpec.class, MARS.ALG_NAME
				+ "KeyGen");
		add(SECRET_KEY_GENERATOR, MARSKeyGenerator.class, MARS.ALG_NAME);
		add(SECRET_KEY_FACTORY, MARSKeyFactory.class, MARS.ALG_NAME);

		add(BLOCK_CIPHER, MARS.class, MARS.ALG_NAME);
	}

	private static void registerMisty1() {
		add(SECRET_KEY_GENERATOR, Misty1KeyGenerator.class, Misty1.ALG_NAME);
		add(SECRET_KEY_FACTORY, Misty1KeyFactory.class, Misty1.ALG_NAME);

		add(BLOCK_CIPHER, Misty1.class, Misty1.ALG_NAME);
	}

	private static void registerRC2() {
		add(ALG_PARAM_SPEC, RC2KeyGenParameterSpec.class, new String[] {
				RC2.ALG_NAME + "KeyGen", RC2_CBC.OID });
		add(SECRET_KEY_GENERATOR, RC2KeyGenerator.class, new String[] {
				RC2.ALG_NAME, RC2_CBC.OID });
		add(SECRET_KEY_FACTORY, RC2KeyFactory.class, new String[] {
				RC2.ALG_NAME, RC2_CBC.OID });

		add(BLOCK_CIPHER, RC2.class, RC2.ALG_NAME);
		add(BLOCK_CIPHER, RC2_CBC.class,
				new String[] { "RC2_CBC", RC2_CBC.OID });
	}

	private static void registerRC5() {
		add(ALG_PARAM_SPEC, RC5KeyGenParameterSpec.class, RC5.ALG_NAME
				+ "KeyGen");
		add(SECRET_KEY_GENERATOR, RC5KeyGenerator.class, RC5.ALG_NAME);
		add(SECRET_KEY_FACTORY, RC5KeyFactory.class, RC5.ALG_NAME);
		add(ALG_PARAM_SPEC, RC5ParameterSpec.class, RC5.ALG_NAME);
		add(ALG_PARAMS, RC5Parameters.class, RC5.ALG_NAME);

		add(BLOCK_CIPHER, RC5.class, RC5.ALG_NAME);
	}

	private static void registerRC6() {
		add(ALG_PARAM_SPEC, RC6KeyGenParameterSpec.class, RC6.ALG_NAME
				+ "KeyGen");
		add(SECRET_KEY_GENERATOR, RC6KeyGenerator.class, RC6.ALG_NAME);
		add(SECRET_KEY_FACTORY, RC6KeyFactory.class, RC6.ALG_NAME);

		add(BLOCK_CIPHER, RC6.class, RC6.ALG_NAME);
	}

	private static void registerSAFERPlus() {
		add(ALG_PARAM_SPEC, SAFERPlusKeyGenParameterSpec.class,
				SAFERPlus.ALG_NAME + "KeyGen");
		add(SECRET_KEY_GENERATOR, SAFERPlusKeyGenerator.class,
				SAFERPlus.ALG_NAME);
		add(SECRET_KEY_FACTORY, SAFERPlusKeyFactory.class, SAFERPlus.ALG_NAME);

		add(BLOCK_CIPHER, SAFERPlus.class, SAFERPlus.ALG_NAME);
	}

	private static void registerSAFERPlusPlus() {
		add(ALG_PARAM_SPEC, SAFERPlusPlusKeyGenParameterSpec.class,
				SAFERPlusPlus.ALG_NAME + "KeyGen");
		add(SECRET_KEY_GENERATOR, SAFERPlusPlusKeyGenerator.class,
				SAFERPlusPlus.ALG_NAME);
		add(SECRET_KEY_FACTORY, SAFERPlusPlusKeyFactory.class,
				SAFERPlusPlus.ALG_NAME);

		add(BLOCK_CIPHER, SAFERPlusPlus.class, SAFERPlusPlus.ALG_NAME);
	}

	private static void registerSerpent() {
		add(ALG_PARAM_SPEC, SerpentKeyGenParameterSpec.class, new String[] {
				Serpent.ALG_NAME + "KeyGen", Serpent.OID });
		add(SECRET_KEY_GENERATOR, SerpentKeyGenerator.class, new String[] {
				Serpent.ALG_NAME, Serpent.OID });
		add(SECRET_KEY_FACTORY, SerpentKeyFactory.class, new String[] {
				Serpent.ALG_NAME, Serpent.OID });

		add(BLOCK_CIPHER, Serpent.class, new String[] { Serpent.ALG_NAME,
				Serpent.OID });

		add(BLOCK_CIPHER, Serpent128_ECB.class, new String[] {
				"Serpent128_ECB", Serpent128_ECB.OID });
		add(BLOCK_CIPHER, Serpent128_CBC.class, new String[] {
				"Serpent128_CBC", Serpent128_CBC.OID });
		add(BLOCK_CIPHER, Serpent128_OFB.class, new String[] {
				"Serpent128_OFB", Serpent128_OFB.OID });
		add(BLOCK_CIPHER, Serpent128_CFB.class, new String[] {
				"Serpent128_CFB", Serpent128_CFB.OID });

		add(BLOCK_CIPHER, Serpent192_ECB.class, new String[] {
				"Serpent192_ECB", Serpent192_ECB.OID });
		add(BLOCK_CIPHER, Serpent192_CBC.class, new String[] {
				"Serpent192_CBC", Serpent192_CBC.OID });
		add(BLOCK_CIPHER, Serpent192_OFB.class, new String[] {
				"Serpent192_OFB", Serpent192_OFB.OID });
		add(BLOCK_CIPHER, Serpent192_CFB.class, new String[] {
				"Serpent192_CFB", Serpent192_CFB.OID });

		add(BLOCK_CIPHER, Serpent256_ECB.class, new String[] {
				"Serpent256_ECB", Serpent256_ECB.OID });
		add(BLOCK_CIPHER, Serpent256_CBC.class, new String[] {
				"Serpent256_CBC", Serpent256_CBC.OID });
		add(BLOCK_CIPHER, Serpent256_OFB.class, new String[] {
				"Serpent256_OFB", Serpent256_OFB.OID });
		add(BLOCK_CIPHER, Serpent256_CFB.class, new String[] {
				"Serpent256_CFB", Serpent256_CFB.OID });
	}

	private static void registerShacal() {
		add(ALG_PARAM_SPEC, ShacalKeyGenParameterSpec.class, Shacal.ALG_NAME
				+ "KeyGen");
		add(SECRET_KEY_GENERATOR, ShacalKeyGenerator.class, Shacal.ALG_NAME);
		add(SECRET_KEY_FACTORY, ShacalKeyFactory.class, Shacal.ALG_NAME);

		add(BLOCK_CIPHER, Shacal.class, Shacal.ALG_NAME);
	}

	private static void registerShacal2() {
		add(ALG_PARAM_SPEC, Shacal2KeyGenParameterSpec.class, Shacal2.ALG_NAME
				+ "KeyGen");
		add(SECRET_KEY_GENERATOR, Shacal2KeyGenerator.class, Shacal2.ALG_NAME);
		add(SECRET_KEY_FACTORY, Shacal2KeyFactory.class, Shacal2.ALG_NAME);

		add(BLOCK_CIPHER, Shacal2.class, Shacal2.ALG_NAME);
	}

	private static void registerTwofish() {
		add(ALG_PARAM_SPEC, TwofishKeyGenParameterSpec.class, Twofish.ALG_NAME
				+ "KeyGen");
		add(SECRET_KEY_GENERATOR, TwofishKeyGenerator.class, Twofish.ALG_NAME);
		add(SECRET_KEY_FACTORY, TwofishKeyFactory.class, Twofish.ALG_NAME);

		add(BLOCK_CIPHER, Twofish.class, Twofish.ALG_NAME);
	}

	private static void registerPBE() {
		/* common */

		add(ALG_PARAM_SPEC, PBEKeyGenParameterSpec.class, "PBEKeyGen");
		add(SECRET_KEY_GENERATOR, PBEKeyGenerator.class, new String[] { "PBE",
				"PBES1", "PBES2" });
		add(SECRET_KEY_FACTORY, PBEKeyFactory.class, new String[] { "PBE",
				"PBES1", "PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID,
				"PbeWithSHA1AndDES_CBC", PBEWithSHA1AndDES_CBC.OID,
				"PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID,
				"PbeWithSHAAnd40BitRC2_CBC", PBEWithSHAAnd40BitRC2_CBC.OID,
				"PBES2", PBES2.OID });

		/* PBES1 */

		add(ALG_PARAM_SPEC, PBEParameterSpec.class, new String[] { "PBE",
				"PBES1", "PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID,
				"PbeWithSHA1AndDES_CBC", PBEWithSHA1AndDES_CBC.OID,
				"PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID,
				"PbeWithSHAAnd40BitRC2_CBC", PBEWithSHAAnd40BitRC2_CBC.OID });
		add(ALG_PARAMS, PBEParameters.class, new String[] { "PBE", "PBES1",
				"PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID,
				"PbeWithSHA1AndDES_CBC", PBEWithSHA1AndDES_CBC.OID,
				"PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID,
				"PbeWithSHAAnd40BitRC2_CBC", PBEWithSHAAnd40BitRC2_CBC.OID });

		add(CIPHER, PBEWithMD5AndDES_CBC.class, new String[] {
				"PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID });
		Registry.add(CIPHER, PBEWithSHA1AndDES_CBC.class, new String[] {
				"PbeWithSHA1AndDES_CBC", PBEWithSHA1AndDES_CBC.OID });
		add(CIPHER, PBEWithSHAAnd3_KeyTripleDES_CBC.class, new String[] {
				"PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID });
		add(CIPHER, PBEWithSHAAnd40BitRC2_CBC.class, new String[] {
				"PbeWithSHAAnd40BitRC2_CBC", PBEWithSHAAnd40BitRC2_CBC.OID });

		/* PBES2 */

		add(ALG_PARAM_SPEC, PBES2ParameterSpec.class, new String[] { "PBES2",
				PBES2.OID });
		add(ALG_PARAMS, PBES2Parameters.class, new String[] { "PBES2",
				PBES2.OID });

		add(CIPHER, PBES2.class, new String[] { "PBES2", PBES2.OID });
	}

	private static void registerKDF() {
		add(ALG_PARAM_SPEC, KDFParameterSpec.class, new String[] { "KDF1",
				"KDF2", "X963" });

		add(KEY_DERIVATION, KDF1.class, "KDF1");
		add(KEY_DERIVATION, KDF2.class, "KDF2");
		add(KEY_DERIVATION, X963.class, "X963");

		/* PBKDF1 */

		add(ALG_PARAM_SPEC, PBEParameterSpec.class, "PBKDF1");
		add(ALG_PARAMS, PBEParameters.class, "PBKDF1");

		add(KEY_DERIVATION, PBKDF1.MD5.class, "PBKDF1_MD5");
		add(KEY_DERIVATION, PBKDF1.SHA1.class, "PBKDF1_SHA1");

		/* PBKDF1_PKCS12 */

		add(ALG_PARAM_SPEC, PBKDF1_PKCS12ParameterSpec.class, "PBKDF1_PKCS12");

		add(KEY_DERIVATION, PBKDF1_PKCS12.MD5.class, "PBKDF1_PKCS12_MD5");
		add(KEY_DERIVATION, PBKDF1_PKCS12.SHA1.class, "PBKDF1_PKCS12_SHA1");

		/* PBKDF2 */

		add(ALG_PARAM_SPEC, PBKDF2ParameterSpec.class, new String[] { "PBKDF2",
				PBKDF2Parameters.OID });
		add(ALG_PARAMS, PBKDF2Parameters.class, new String[] { "PBKDF2",
				PBKDF2Parameters.OID });

		add(KEY_DERIVATION, PBKDF2.class, new String[] { "PBKDF2", PBKDF2.OID });
	}

	private static void registerBBS() {
		add(SECURE_RANDOM, BBSRandom.class, "BBSRandom");
	}

	private static void registerSHA1PRNG() {
		add(SECURE_RANDOM, SHA1PRNG.class, "SHA1PRNG");
	}

}
