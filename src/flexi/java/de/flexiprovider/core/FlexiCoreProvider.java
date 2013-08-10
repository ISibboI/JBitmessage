/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core;

import de.flexiprovider.api.FlexiProvider;
import de.flexiprovider.common.mode.ModeParameterGenerator;
import de.flexiprovider.common.mode.ModeParameters;
import de.flexiprovider.core.camellia.Camellia;
import de.flexiprovider.core.camellia.CamelliaKeyFactory;
import de.flexiprovider.core.camellia.CamelliaKeyGenerator;
import de.flexiprovider.core.desede.DESede;
import de.flexiprovider.core.desede.DESedeKeyFactory;
import de.flexiprovider.core.desede.DESedeKeyGenerator;
import de.flexiprovider.core.dsa.DSAKeyFactory;
import de.flexiprovider.core.dsa.DSAKeyPairGenerator;
import de.flexiprovider.core.dsa.DSAParameterGenerator;
import de.flexiprovider.core.dsa.DSAParameters;
import de.flexiprovider.core.dsa.DSASignature;
import de.flexiprovider.core.elgamal.ElGamal;
import de.flexiprovider.core.elgamal.ElGamalKeyFactory;
import de.flexiprovider.core.elgamal.ElGamalKeyPairGenerator;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamal;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamalKeyFactory;
import de.flexiprovider.core.elgamal.semanticallysecure.SSVElGamalKeyPairGenerator;
import de.flexiprovider.core.idea.IDEA;
import de.flexiprovider.core.idea.IDEAKeyFactory;
import de.flexiprovider.core.idea.IDEAKeyGenerator;
import de.flexiprovider.core.kdf.PBKDF2Parameters;
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
import de.flexiprovider.core.mersa.MeRSAKeyPairGenerator;
import de.flexiprovider.core.mersa.MeRSASignaturePSS;
import de.flexiprovider.core.misty1.Misty1;
import de.flexiprovider.core.misty1.Misty1KeyFactory;
import de.flexiprovider.core.misty1.Misty1KeyGenerator;
import de.flexiprovider.core.mprsa.MpRSA;
import de.flexiprovider.core.mprsa.MpRSAKeyPairGenerator;
import de.flexiprovider.core.mprsa.MpRSASignaturePSS;
import de.flexiprovider.core.pbe.PBEKeyFactory;
import de.flexiprovider.core.pbe.PBEKeyGenerator;
import de.flexiprovider.core.pbe.PBEParameters;
import de.flexiprovider.core.pbe.PBES2;
import de.flexiprovider.core.pbe.PBES2Parameters;
import de.flexiprovider.core.pbe.PBEWithMD5AndDES_CBC;
import de.flexiprovider.core.pbe.PBEWithSHA1AndDES_CBC;
import de.flexiprovider.core.pbe.PBEWithSHAAnd3_KeyTripleDES_CBC;
import de.flexiprovider.core.pbe.PBEWithSHAAnd40BitRC2_CBC;
import de.flexiprovider.core.random.BBSRandom;
import de.flexiprovider.core.rbrsa.RbRSAKeyPairGenerator;
import de.flexiprovider.core.rc2.RC2;
import de.flexiprovider.core.rc2.RC2.RC2_CBC;
import de.flexiprovider.core.rc2.RC2KeyFactory;
import de.flexiprovider.core.rc2.RC2KeyGenerator;
import de.flexiprovider.core.rc5.RC5;
import de.flexiprovider.core.rc5.RC5KeyFactory;
import de.flexiprovider.core.rc5.RC5KeyGenerator;
import de.flexiprovider.core.rc6.RC6;
import de.flexiprovider.core.rc6.RC6KeyFactory;
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
import de.flexiprovider.core.rijndael.RijndaelKeyGenerator;
import de.flexiprovider.core.rijndael.RijndaelParameters;
import de.flexiprovider.core.rprimersa.RprimeRSAKeyPairGenerator;
import de.flexiprovider.core.rsa.PSSParameters;
import de.flexiprovider.core.rsa.RSAKeyFactory;
import de.flexiprovider.core.rsa.RSAKeyPairGenerator;
import de.flexiprovider.core.rsa.RSAOAEPParameters;
import de.flexiprovider.core.rsa.RSASignaturePKCS1v15;
import de.flexiprovider.core.rsa.RSASignaturePSS;
import de.flexiprovider.core.rsa.RSA_PKCS1_v1_5;
import de.flexiprovider.core.rsa.RSA_PKCS1_v2_1;
import de.flexiprovider.core.rsa.SSLSignature;
import de.flexiprovider.core.rsa.UnlimitedLengthRSA;
import de.flexiprovider.core.saferplus.SAFERPlus;
import de.flexiprovider.core.saferplus.SAFERPlusKeyFactory;
import de.flexiprovider.core.saferplus.SAFERPlusKeyGenerator;
import de.flexiprovider.core.saferplusplus.SAFERPlusPlus;
import de.flexiprovider.core.saferplusplus.SAFERPlusPlusKeyFactory;
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
import de.flexiprovider.core.serpent.SerpentKeyGenerator;
import de.flexiprovider.core.shacal.Shacal;
import de.flexiprovider.core.shacal.ShacalKeyFactory;
import de.flexiprovider.core.shacal.ShacalKeyGenerator;
import de.flexiprovider.core.shacal2.Shacal2;
import de.flexiprovider.core.shacal2.Shacal2KeyFactory;
import de.flexiprovider.core.shacal2.Shacal2KeyGenerator;
import de.flexiprovider.core.twofish.Twofish;
import de.flexiprovider.core.twofish.TwofishKeyFactory;
import de.flexiprovider.core.twofish.TwofishKeyGenerator;

/**
 * This class is the provider for public key algorithms of which security is
 * based on the difficulty of factoring large integers and on computing discrete
 * logarithms in the multiplicative group of a finite prime field. It also
 * provides symmetric encryption schemes, hash functions, and generation of
 * pseudo random numbers.
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
 * import de.flexiprovider.core.FlexiCoreProvider;
 * 
 * Security.addProvider(new FlexiCoreProvider());
 * </pre>
 * 
 * The provider is registered statically by adding an entry to the
 * <tt>java.security</tt> properties file (usually
 * <tt>$JAVA_HOME/lib/security/java.security</tt>). See that file for
 * instructions.
 * 
 * <h4>Contents of the FlexiCoreProvider</h4>
 * 
 * <ul type=circle>
 * 
 * <li>Asymmetric (public key) encryption:
 * <ul type = square>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Cipher.RSA</a> (PKCS1 v1.5)</li>
 * <li><a href = rsa/RSA_PKCS1_v2_1.html>Cipher.RSA_PKCS1_v2_1</a> (OAEP)</li>
 * <li><a href = elgamal/ElGamal.html>Cipher.ElGamal</a></li>
 * </ul>
 * </li>
 * 
 * <li>Digital signatures:
 * <ul type = square>
 * <li><a href = dsa/DSASignature.html>Signature.DSASignature</a></li>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Signature.MD5withRSA</a></li>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Signature.SHA1withRSA</a></li>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Signature.SHA224withRSA</a></li>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Signature.SHA256withRSA</a></li>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Signature.SHA384withRSA</a></li>
 * <li><a href = rsa/RSA_PKCS1_v1_5.html>Signature.SHA512withRSA</a></li>
 * <li><a href = dsa/RawDSA.html>Signature.RawDSA</a></li>
 * <li><a href = rsa/SSLSignature.html>Signature.SSL_MD5andSHA1withRSA</a></li>
 * </ul>
 * </li>
 * 
 * <li>Symmetric encryption:
 * <ul type = square>
 * <li><a href = desede/DESede.html>Cipher.DESede</a></li>
 * <li><a href = idea/IDEA.html>Cipher.IDEA</a></li>
 * <li><a href = rc2/RC2.html>Cipher.RC2</a></li>
 * <li><a href = rc5/RC5.html>Cipher.RC5</a></li>
 * <li><a href = rc6/RC6.html>Cipher.RC6</a></li>
 * <li><a href = mars/MARS.html>Cipher.MARS</a></li>
 * <li><a href = serpent/Serpent.html>Cipher.Serpent</a></li>
 * <li><a href = twofish/Twofish.html>Cipher.Twofish</a></li>
 * <li><a href = rijndael/Rijndael.html>Cipher.Rijndael</a></li>
 * <li><a href = saferplus/SAFERPlus.html>Cipher.SAFER+</a></li>
 * <li><a href = saferplusplus/SAFERPlusPlus.html>Cipher.SAFER++</a></li>
 * <li><a href = pbe/PBEWithMD5AndDES_CBC.html>Cipher.PbeWithMD5AndDES_CBC</a></li>
 * <li><a href = pbe/PBEWithSHA1andDES_CBC.html>Cipher.PbeWithSHA1andDES_CBC</a>
 * </li>
 * <li><a href = pbe/PBEWithSHAAnd3_KeyTripleDES_CBC.html>Cipher.
 * PbeWithSHAAnd3_KeyTripleDES_CBC</a></li>
 * <li><a href =
 * pbe/PBEWithSHAAnd40BitRC2_CBC.html>Cipher.PbeWithSHAAnd40BitRC2_CBC</a></li>
 * </ul>
 * </li>
 * 
 * <li>Modes of operation for symmetric encryption:
 * <ul type = square>
 * <li><a href = mode/ECB.html>Mode.ECB</a></li>
 * <li><a href = mode/CBC.html>Mode.CBC</a></li>
 * <li><a href = mode/CFB.html>Mode.CFB</a></li>
 * <li><a href = mode/OFB.html>Mode.OFB</a></li>
 * <li><a href = mode/CTR.html>Mode.CTR</a></li>
 * </ul>
 * </li>
 * 
 * <li>Padding schemes for symmetric encryption:
 * <ul type = square>
 * <li><a href = padding/NoPadding.html>Padding.NoPadding</a></li>
 * <li><a href =
 * padding/OneAndZeroesPadding.html>Padding.OneAndZeroesPadding</a></li>
 * <li><a href = padding/PKCS5Padding.html>Padding.PKCS5Padding</a></li>
 * </ul>
 * </li>
 * 
 * <li>Message digests:
 * <ul type = square>
 * <li><a href = md/NullDigest.html>MessageDigest.NullDigest</a></li>
 * <li><a href = md/SHA1.html>MessageDigest.SHA1</a></li>
 * <li><a href = md/SHA224.html>MessageDigest.SHA224</a></li>
 * <li><a href = md/SHA256.html>MessageDigest.SHA256</a></li>
 * <li><a href = md/SHA384.html>MessageDigest.SHA384</a></li>
 * <li><a href = md/SHA512.html>MessageDigest.SHA512</a></li>
 * <li><a href = md/MD4.html>MessageDigest.MD4</a></li>
 * <li><a href = md/MD5.html>MessageDigest.MD5</a></li>
 * <li><a href = md/RIPEMD128.html>MessageDigest.RIPEMD128</a></li>
 * <li><a href = md/RIPEMD160.html>MessageDigest.RIPEMD160</a></li>
 * <li><a href = md/RIPEMD256.html>MessageDigest.RIPEMD256</a></li>
 * <li><a href = md/RIPEMD320.html>MessageDigest.RIPEMD320</a></li>
 * <li><a href = md/Tiger.html>MessageDigest.Tiger</a></li>
 * <li><a href = md/DHA256.html>MessageDigest.DHA256</a></li>
 * <li><a href = md/FORK256.html>MessageDigest.FORK256</a></li>
 * </ul>
 * </li>
 * 
 * <li>Message authentication codes:
 * <ul type = square>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacAES128</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacAES192</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacAES256</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacCamellia</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacDESede</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacIDEA</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacMARS</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacRC2</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacRC5</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacRC6</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacSAFER+</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacSAFER++</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacSerpent</a></li>
 * <li><a href = mac/CBCMac.html>Mac.CBCmacTwofish</a></li>
 * <li><a href = mac/CMac.html>Mac.CmacDESede</a></li>
 * <li><a href = mac/CMac.html>Mac.CmacAES128</a></li>
 * <li><a href = mac/CMac.html>Mac.CmacAES192</a></li>
 * <li><a href = mac/CMac.html>Mac.CmacAES256</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacSHA1</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacSHA224</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacSHA256</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacSHA384</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacSHA512</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacMD4</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacMD5</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacRIPEMD128</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacRIPEMD160</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacRIPEMD256</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacRIPEMD320</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacTiger</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacDHA256</a></li>
 * <li><a href = mac/HMac.html>Mac.HmacFORK256</a></li>
 * <li><a href = mac/TwoTrackMac.html>Mac.TTmac32</a></li>
 * <li><a href = mac/TwoTrackMac.html>Mac.TTmac64</a></li>
 * <li><a href = mac/TwoTrackMac.html>Mac.TTmac96</a></li>
 * <li><a href = mac/TwoTrackMac.html>Mac.TTmac128</a></li>
 * <li><a href = mac/TwoTrackMac.html>Mac.TTmac160</a></li>
 * </ul>
 * </li>
 * 
 * <li>Pseudo random number generators:
 * <ul type = square>
 * <li><a href = random/BBSRandom.html>SecureRandom.BBSRandom</a>
 * (Blum-Blum-Shub)</li>
 * </ul>
 * </li>
 * 
 * </ul>
 * 
 * @author <a href="mailto:info@flexiprovider.de">FlexiProvider group</a>.
 * @version 1.7.6
 */
public class FlexiCoreProvider extends FlexiProvider {

	/**
	 * Constructor. Register all algorithms for FlexiAPI and JCA.
	 */
	public FlexiCoreProvider() {
		super("FlexiCore", 1.76, "");

		// ------------------------------------------------
		// register algorithms for FlexiAPI
		// ------------------------------------------------

		CoreRegistry.registerAlgorithms();

		// ------------------------------------------------
		// register algorithms for JCA/JCE
		// ------------------------------------------------

		registerCommon();
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
		registerCBCMAC();
		registerCMAC();
		registerHMAC();
		registerTTMAC();
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
		registerBBS();
	}

	private void registerCommon() {
		add(ALG_PARAMS, ModeParameters.class, new String[] { "Mode", "IV" });
		add(ALG_PARAM_GENERATOR, ModeParameterGenerator.class, new String[] {
				"Mode", "IV" });
	}

	private void registerDSA() {
		add(KEY_PAIR_GENERATOR, DSAKeyPairGenerator.class, new String[] {
				"DSA", DSAKeyFactory.OID, DSAKeyFactory.OID2 });
		add(KEY_FACTORY, DSAKeyFactory.class, new String[] { "DSA",
				DSAKeyFactory.OID, DSAKeyFactory.OID2 });
		add(ALG_PARAMS, DSAParameters.class, new String[] { "DSA",
				DSAParameters.OID, DSAParameters.OID2 });
		add(ALG_PARAM_GENERATOR, DSAParameterGenerator.class, new String[] {
				"DSA", DSAParameterGenerator.OID, DSAParameterGenerator.OID2 });

		// DSA signature with SHA1
		add(SIGNATURE, DSASignature.SHA1.class, new String[] { "SHA1withDSA",
				"SHA1/DSA", "SHAwithDSA", "SHA/DSA", "DSS",
				DSASignature.SHA1.OID, DSASignature.SHA1.OID2,
				DSASignature.SHA1.OID3 });
		addReverseOID(SIGNATURE, "SHA1withDSA", DSASignature.SHA1.OID);

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
				"RAWDSA" });
	}

	private void registerRSA() {
		// common
		add(KEY_PAIR_GENERATOR, RSAKeyPairGenerator.class, new String[] {
				"RSA", RSAKeyFactory.OID });
		add(KEY_FACTORY, RSAKeyFactory.class, new String[] { "RSA", "MpRSA",
				"RbRSA", "RprimeRSA", RSAKeyFactory.OID });

		// ---------------------------------------------------------

		// RSA cipher according to PKCS #1 v1.5
		add(CIPHER, RSA_PKCS1_v1_5.class, new String[] { "RSA",
				"RSA_PKCS1_v1_5", RSA_PKCS1_v1_5.OID });
		addReverseOID(CIPHER, "RSA", RSA_PKCS1_v1_5.OID);

		// RSA Cipher with unlimited length (in ECB mode)
		add(CIPHER, UnlimitedLengthRSA.class,
				new String[] { UnlimitedLengthRSA.NAME });

		// ---------------------------------------------------------

		// RSA cipher according to PKCS #1 v2.1 (RSA-OAEP)
		add(ALG_PARAMS, RSAOAEPParameters.class, new String[] { "RSA-OAEP",
				"RSA_PKCS1_v2_1", RSA_PKCS1_v2_1.OID });
		addReverseOID(ALG_PARAMS, "RSA-OAEP", RSA_PKCS1_v2_1.OID);

		add(CIPHER, RSA_PKCS1_v2_1.class, new String[] { "RSA-OAEP",
				"RSA_PKCS1_v2_1", RSA_PKCS1_v2_1.OID });
		addReverseOID(CIPHER, "RSA-OAEP", RSA_PKCS1_v2_1.OID);

		// ---------------------------------------------------------

		/*
		 * RSA-SSA signature according to PKCS #1 v1.5
		 */

		// RSA-SSA signature with MD5
		add(SIGNATURE, RSASignaturePKCS1v15.MD5.class, new String[] {
				"MD5withRSA", "MD5/RSA", RSASignaturePKCS1v15.MD5.OID,
				RSASignaturePKCS1v15.MD5.ALTERNATIVE_OID });
		addReverseOID(SIGNATURE, "MD5withRSA", RSASignaturePKCS1v15.MD5.OID);

		// RSA-SSA signature with SHA1
		add(SIGNATURE, RSASignaturePKCS1v15.SHA1.class, new String[] {
				"SHA1withRSA", "SHA1/RSA", "SHA/RSA",
				RSASignaturePKCS1v15.SHA1.OID,
				RSASignaturePKCS1v15.SHA1.ALTERNATIVE_OID });
		addReverseOID(SIGNATURE, "SHA1withRSA", RSASignaturePKCS1v15.SHA1.OID);

		// RSA-SSA signature with SHA224
		add(SIGNATURE, RSASignaturePKCS1v15.SHA224.class,
				new String[] { "SHA224withRSA", "SHA224/RSA",
						RSASignaturePKCS1v15.SHA224.OID });
		addReverseOID(SIGNATURE, "SHA224withRSA",
				RSASignaturePKCS1v15.SHA224.OID);

		// RSA-SSA signature with SHA256
		add(SIGNATURE, RSASignaturePKCS1v15.SHA256.class,
				new String[] { "SHA256withRSA", "SHA256/RSA",
						RSASignaturePKCS1v15.SHA256.OID });
		addReverseOID(SIGNATURE, "SHA256withRSA",
				RSASignaturePKCS1v15.SHA256.OID);

		// RSA-SSA signature with SHA384
		add(SIGNATURE, RSASignaturePKCS1v15.SHA384.class,
				new String[] { "SHA384withRSA", "SHA384/RSA",
						RSASignaturePKCS1v15.SHA384.OID });
		addReverseOID(SIGNATURE, "SHA384withRSA",
				RSASignaturePKCS1v15.SHA384.OID);

		// RSA-SSA signature with SHA512
		add(SIGNATURE, RSASignaturePKCS1v15.SHA512.class,
				new String[] { "SHA512withRSA", "SHA512/RSA",
						RSASignaturePKCS1v15.SHA512.OID });
		addReverseOID(SIGNATURE, "SHA512withRSA",
				RSASignaturePKCS1v15.SHA512.OID);

		// RSA-SSA signature with RIPEMD160
		add(SIGNATURE, RSASignaturePKCS1v15.RIPEMD160.class, new String[] {
				"RIPEMD160withRSA", "RIPEMD160/RSA",
				RSASignaturePKCS1v15.RIPEMD160.OID });
		addReverseOID(SIGNATURE, "RIPEMD160withRSA",
				RSASignaturePKCS1v15.RIPEMD160.OID);

		// ---------------------------------------------------------

		/*
		 * RSA-SSA signature according to PKCS #1 v1.5 with precomputed hashes.
		 * Distinct registrations are needed even in this case since the OID of
		 * the message digest is embedded into the signature.
		 */

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
		add(ALG_PARAMS, PSSParameters.class, new String[] { "RSASSA-PSS",
				RSASignaturePSS.OID });
		addReverseOID(ALG_PARAMS, "RSASSA-PSS", RSASignaturePSS.OID);

		add(SIGNATURE, RSASignaturePSS.class, new String[] { "RSASSA-PSS",
				RSASignaturePSS.OID });
		addReverseOID(ALG_PARAMS, "RSASSA-PSS", RSASignaturePSS.OID);

		// ---------------------------------------------------------

		// SSL Signature (MD5 and SHA1 hash without DigestInfo)
		add(SIGNATURE, SSLSignature.class, "SSL_MD5andSHA1withRSA");

		// ---------------------------------------------------------

		/* Multi-exponent RSA */

		add(KEY_PAIR_GENERATOR, MeRSAKeyPairGenerator.class, "MeRSA");
		add(KEY_FACTORY, MeRSAKeyFactory.class, "MeRSA");

		add(CIPHER, MeRSA.class, "MeRSA");

		add(SIGNATURE, MeRSASignaturePSS.class, "MeRSA");

		// ---------------------------------------------------------

		/* Multi-prime RSA */

		add(KEY_PAIR_GENERATOR, MpRSAKeyPairGenerator.class, "MpRSA");
		// key factory is same as for standard RSA (registered above)

		add(CIPHER, MpRSA.class, "MpRSA");

		add(SIGNATURE, MpRSASignaturePSS.class, "MpRSA");

		// ---------------------------------------------------------

		/* Rebalanced RSA */

		add(KEY_PAIR_GENERATOR, RbRSAKeyPairGenerator.class, "RbRSA");
		// key factory is same as for standard RSA (registered above)

		add(CIPHER, RSA_PKCS1_v2_1.class, "RbRSA");

		add(SIGNATURE, RSASignaturePSS.class, "RbRSA");

		// ---------------------------------------------------------

		/* Rprime RSA (Rebalanced multi-prime RSA) */

		add(KEY_PAIR_GENERATOR, RprimeRSAKeyPairGenerator.class, "RprimeRSA");
		// key factory is same as for standard RSA (registered above)

		add(CIPHER, MpRSA.class, "RprimeRSA");

		add(SIGNATURE, MpRSASignaturePSS.class, "RprimeRSA");
	}

	private void registerElGamal() {
		add(KEY_PAIR_GENERATOR, ElGamalKeyPairGenerator.class, new String[] {
				ElGamal.ALG_NAME, ElGamalKeyPairGenerator.OID });
		add(KEY_FACTORY, ElGamalKeyFactory.class, new String[] {
				ElGamal.ALG_NAME, ElGamalKeyFactory.OID });

		add(CIPHER, ElGamal.class,
				new String[] { ElGamal.ALG_NAME, ElGamal.OID });
		addReverseOID(CIPHER, ElGamal.ALG_NAME, ElGamal.OID);
	}

	private void registerSSVElGamal() {
		add(KEY_PAIR_GENERATOR, SSVElGamalKeyPairGenerator.class,
				SSVElGamal.ALG_NAME);
		add(KEY_FACTORY, SSVElGamalKeyFactory.class, SSVElGamal.ALG_NAME);

		add(CIPHER, SSVElGamal.class, SSVElGamal.ALG_NAME);
	}

	private void registerSHAfamily() {
		// SHA1
		add(MESSAGE_DIGEST, SHA1.class, new String[] { SHA1.ALG_NAME,
				SHA1.ALG_NAME2, SHA1.OID });
		addReverseOID(MESSAGE_DIGEST, SHA1.ALG_NAME, SHA1.OID);

		// SHA224
		add(MESSAGE_DIGEST, SHA224.class, new String[] { SHA224.ALG_NAME,
				SHA224.OID });
		addReverseOID(MESSAGE_DIGEST, SHA224.ALG_NAME, SHA224.OID);

		// SHA256
		add(MESSAGE_DIGEST, SHA256.class, new String[] { SHA256.ALG_NAME,
				SHA256.OID });
		addReverseOID(MESSAGE_DIGEST, SHA256.ALG_NAME, SHA256.OID);

		// SHA384
		add(MESSAGE_DIGEST, SHA384.class, new String[] { SHA384.ALG_NAME,
				SHA384.OID });
		addReverseOID(MESSAGE_DIGEST, SHA384.ALG_NAME, SHA384.OID);

		// SHA512
		add(MESSAGE_DIGEST, SHA512.class, new String[] { SHA512.ALG_NAME,
				SHA512.OID });
		addReverseOID(MESSAGE_DIGEST, SHA512.ALG_NAME, SHA512.OID);
	}

	private void registerMDfamily() {
		// MD4
		add(MESSAGE_DIGEST, MD4.class, new String[] { MD4.ALG_NAME, MD4.OID });
		addReverseOID(MESSAGE_DIGEST, MD4.ALG_NAME, MD4.OID);

		// MD5
		add(MESSAGE_DIGEST, MD5.class, new String[] { MD5.ALG_NAME, MD5.OID });
		addReverseOID(MESSAGE_DIGEST, MD5.ALG_NAME, MD5.OID);
	}

	private void registerRIPEMDfamily() {
		// RIPEMD 128
		add(MESSAGE_DIGEST, RIPEMD128.class, new String[] { RIPEMD128.ALG_NAME,
				RIPEMD128.OID });
		addReverseOID(MESSAGE_DIGEST, RIPEMD128.ALG_NAME, RIPEMD128.OID);

		// RIPEMD 160
		add(MESSAGE_DIGEST, RIPEMD160.class, new String[] { RIPEMD160.ALG_NAME,
				RIPEMD160.OID });
		addReverseOID(MESSAGE_DIGEST, RIPEMD160.ALG_NAME, RIPEMD160.OID);

		// RIPEMD 256
		add(MESSAGE_DIGEST, RIPEMD256.class, new String[] { RIPEMD256.ALG_NAME,
				RIPEMD256.OID });
		addReverseOID(MESSAGE_DIGEST, RIPEMD256.ALG_NAME, RIPEMD256.OID);

		// RIPEMD 320 (TODO: OID)
		add(MESSAGE_DIGEST, RIPEMD320.class, RIPEMD320.ALG_NAME);
	}

	private void registerTiger() {
		add(MESSAGE_DIGEST, Tiger.class, new String[] { Tiger.ALG_NAME,
				Tiger.OID });
		addReverseOID(MESSAGE_DIGEST, Tiger.ALG_NAME, Tiger.OID);
	}

	private void registerDHA256() {
		add(MESSAGE_DIGEST, DHA256.class, DHA256.ALG_NAME);
	}

	private void registerFORK256() {
		add(MESSAGE_DIGEST, FORK256.class, FORK256.ALG_NAME);
	}

	private void registerSWIFFTX() {
		add(MESSAGE_DIGEST, SWIFFTX224.class, SWIFFTX224.ALG_NAME);
		add(MESSAGE_DIGEST, SWIFFTX256.class, SWIFFTX256.ALG_NAME);
		add(MESSAGE_DIGEST, SWIFFTX384.class, SWIFFTX384.ALG_NAME);
		add(MESSAGE_DIGEST, SWIFFTX512.class, SWIFFTX512.ALG_NAME);
	}

	private void registerVSH() {
		add(MESSAGE_DIGEST, VSH.class, VSH.ALG_NAME);
	}

	private void registerCBCMAC() {
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

	private void registerCMAC() {
		add(MAC, CMac.DESede.class, CMac.DESede.ALG_NAME);
		add(MAC, CMac.AES128.class, CMac.AES128.ALG_NAME);
		add(MAC, CMac.AES192.class, CMac.AES192.ALG_NAME);
		add(MAC, CMac.AES256.class, CMac.AES256.ALG_NAME);
	}

	private void registerHMAC() {
		add(SECRET_KEY_FACTORY, HMacKeyFactory.class, new String[] { "Hmac",
				"HmacSHA1", HMac.SHA1.OID, HMac.SHA1.PKCS5_OID, "HmacSHA224",
				"HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacMD4", "HmacMD5",
				HMac.MD5.OID, "HmacRIPEMD128", "HmacRIPEMD160",
				HMac.RIPEMD160.OID, "HmacRIPEMD256", "HmacRIPEMD320",
				"HmacTiger", HMac.Tiger.OID, "HmacDHA256", "HmacFORK256" });

		// HmacSHA1
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.SHA1.class, new String[] {
				"HmacSHA1", HMac.SHA1.OID, HMac.SHA1.PKCS5_OID });
		add(MAC, HMac.SHA1.class, new String[] { "HmacSHA1", HMac.SHA1.OID });

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
		add(MAC, HMac.MD5.class, new String[] { "MD5", HMac.MD5.OID });

		// HmacRIPEMD128
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.RIPEMD128.class,
				"HmacRIPEMD128");
		add(MAC, HMac.RIPEMD128.class, "HmacRIPEMD128");

		// HmacRIPEMD160
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.RIPEMD160.class,
				new String[] { "HmacRIPEMD160", HMac.RIPEMD160.OID });
		add(MAC, HMac.RIPEMD160.class, new String[] { "RIPEMD160",
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
		add(MAC, HMac.Tiger.class, new String[] { "Tiger", HMac.Tiger.OID });

		// HmacDHA256
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.DHA256.class, "HmacDHA256");
		add(MAC, HMac.DHA256.class, "HmacDHA256");

		// HmacFORK256
		add(SECRET_KEY_GENERATOR, HMacKeyGenerator.FORK256.class, "HmacFORK256");
		add(MAC, HMac.FORK256.class, "HmacFORK256");
	}

	private void registerTTMAC() {
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

	private void registerAESRijndael() {
		/* common */

		add(SECRET_KEY_GENERATOR, RijndaelKeyGenerator.class, new String[] {
				Rijndael.ALG_NAME, AES.ALG_NAME, AES.OID });
		add(SECRET_KEY_FACTORY, RijndaelKeyFactory.class, new String[] {
				Rijndael.ALG_NAME, AES.ALG_NAME, AES.OID });

		/* AES */

		add(CIPHER, AES.class, new String[] { AES.ALG_NAME, AES.OID });
		addReverseOID(CIPHER, AES.ALG_NAME, AES.OID);

		add(CIPHER, AES128_ECB.class, new String[] { AES128_ECB.ALG_NAME,
				AES128_ECB.OID });
		addReverseOID(CIPHER, AES128_ECB.ALG_NAME, AES128_ECB.OID);
		add(CIPHER, AES128_CBC.class, new String[] { AES128_CBC.ALG_NAME,
				AES128_CBC.OID });
		addReverseOID(CIPHER, AES128_CBC.ALG_NAME, AES128_CBC.OID);
		add(CIPHER, AES128_OFB.class, new String[] { AES128_OFB.ALG_NAME,
				AES128_OFB.OID });
		addReverseOID(CIPHER, AES128_OFB.ALG_NAME, AES128_OFB.OID);
		add(CIPHER, AES128_CFB.class, new String[] { AES128_CFB.ALG_NAME,
				AES128_CFB.OID });
		addReverseOID(CIPHER, AES128_CFB.ALG_NAME, AES128_CFB.OID);

		add(CIPHER, AES192_ECB.class, new String[] { AES192_ECB.ALG_NAME,
				AES192_ECB.OID });
		addReverseOID(CIPHER, AES192_ECB.ALG_NAME, AES192_ECB.OID);
		add(CIPHER, AES192_CBC.class, new String[] { AES192_CBC.ALG_NAME,
				AES192_CBC.OID });
		addReverseOID(CIPHER, AES192_CBC.ALG_NAME, AES192_CBC.OID);
		add(CIPHER, AES192_OFB.class, new String[] { AES192_OFB.ALG_NAME,
				AES192_OFB.OID });
		addReverseOID(CIPHER, AES192_OFB.ALG_NAME, AES192_OFB.OID);
		add(CIPHER, AES192_CFB.class, new String[] { AES192_CFB.ALG_NAME,
				AES192_CFB.OID });
		addReverseOID(CIPHER, AES192_CFB.ALG_NAME, AES192_CFB.OID);

		add(CIPHER, AES256_ECB.class, new String[] { AES256_ECB.ALG_NAME,
				AES256_ECB.OID });
		addReverseOID(CIPHER, AES256_ECB.ALG_NAME, AES256_ECB.OID);
		add(CIPHER, AES256_CBC.class, new String[] { AES256_CBC.ALG_NAME,
				AES256_CBC.OID });
		addReverseOID(CIPHER, AES256_CBC.ALG_NAME, AES256_CBC.OID);
		add(CIPHER, AES256_OFB.class, new String[] { AES256_OFB.ALG_NAME,
				AES256_OFB.OID });
		addReverseOID(CIPHER, AES256_OFB.ALG_NAME, AES256_OFB.OID);
		add(CIPHER, AES256_CFB.class, new String[] { AES256_CFB.ALG_NAME,
				AES256_CFB.OID });
		addReverseOID(CIPHER, AES256_CFB.ALG_NAME, AES256_CFB.OID);

		/* Rijndael */

		add(ALG_PARAMS, RijndaelParameters.class, Rijndael.ALG_NAME);

		add(CIPHER, Rijndael.class, Rijndael.ALG_NAME);
	}

	private void registerCamellia() {
		add(SECRET_KEY_GENERATOR, CamelliaKeyGenerator.class, Camellia.ALG_NAME);
		add(SECRET_KEY_FACTORY, CamelliaKeyFactory.class, Camellia.ALG_NAME);

		add(CIPHER, Camellia.class, Camellia.ALG_NAME);

		// OIDs defined by RFC 3657
		add(CIPHER, Camellia.Camellia128_CBC.class, new String[] {
				"Camellia128_CBC", Camellia.Camellia128_CBC.OID });
		addReverseOID(CIPHER, "Camellia128_CBC", Camellia.Camellia128_CBC.OID);

		add(CIPHER, Camellia.Camellia192_CBC.class, new String[] {
				"Camellia192_CBC", Camellia.Camellia192_CBC.OID });
		addReverseOID(CIPHER, "Camellia192_CBC", Camellia.Camellia192_CBC.OID);

		add(CIPHER, Camellia.Camellia256_CBC.class, new String[] {
				"Camellia256_CBC", Camellia.Camellia256_CBC.OID });
		addReverseOID(CIPHER, "Camellia256_CBC", Camellia.Camellia256_CBC.OID);
	}

	private void registerDESede() {
		add(SECRET_KEY_GENERATOR, DESedeKeyGenerator.class, new String[] {
				DESede.ALG_NAME, DESede.DESede_CBC.OID });
		add(SECRET_KEY_FACTORY, DESedeKeyFactory.class, new String[] {
				DESede.ALG_NAME, DESede.DESede_CBC.OID });

		add(CIPHER, DESede.class, DESede.ALG_NAME);
		add(CIPHER, DESede.DESede_CBC.class, new String[] {
				DESede.DESede_CBC.ALG_NAME, DESede.DESede_CBC.OID });
		addReverseOID(CIPHER, DESede.DESede_CBC.ALG_NAME, DESede.DESede_CBC.OID);
	}

	private void registerIDEA() {
		add(SECRET_KEY_GENERATOR, IDEAKeyGenerator.class, new String[] {
				IDEA.ALG_NAME, IDEA.OID });
		add(SECRET_KEY_FACTORY, IDEAKeyFactory.class, new String[] {
				IDEA.ALG_NAME, IDEA.OID });

		add(CIPHER, IDEA.class, new String[] { IDEA.ALG_NAME, IDEA.OID });

		add(CIPHER, IDEA.IDEA_ECB.class, new String[] { "IDEA_ECB",
				IDEA.IDEA_ECB.OID });
		addReverseOID(CIPHER, "IDEA_ECB", IDEA.IDEA_ECB.OID);
		add(CIPHER, IDEA.IDEA_CBC.class, new String[] { "IDEA_CBC",
				IDEA.IDEA_CBC.OID });
		addReverseOID(CIPHER, "IDEA_CBC", IDEA.IDEA_CBC.OID);
		add(CIPHER, IDEA.IDEA_CFB.class, new String[] { "IDEA_CFB",
				IDEA.IDEA_CFB.OID });
		addReverseOID(CIPHER, "IDEA_CFB", IDEA.IDEA_CFB.OID);
		add(CIPHER, IDEA.IDEA_OFB.class, new String[] { "IDEA_OFB",
				IDEA.IDEA_OFB.OID });
		addReverseOID(CIPHER, "IDEA_OFB", IDEA.IDEA_OFB.OID);
	}

	private void registerMARS() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, MARSKeyGenerator.class, MARS.ALG_NAME);
		add(SECRET_KEY_FACTORY, MARSKeyFactory.class, MARS.ALG_NAME);

		add(CIPHER, MARS.class, MARS.ALG_NAME);
	}

	private void registerMisty1() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, Misty1KeyGenerator.class, Misty1.ALG_NAME);
		add(SECRET_KEY_FACTORY, Misty1KeyFactory.class, Misty1.ALG_NAME);

		add(CIPHER, Misty1.class, Misty1.ALG_NAME);
	}

	private void registerRC2() {
		add(SECRET_KEY_GENERATOR, RC2KeyGenerator.class, new String[] {
				RC2.ALG_NAME, RC2_CBC.OID });
		add(SECRET_KEY_FACTORY, RC2KeyFactory.class, new String[] {
				RC2.ALG_NAME, RC2_CBC.OID });

		add(CIPHER, RC2.class, RC2.ALG_NAME);
		add(CIPHER, RC2_CBC.class, new String[] { "RC2_CBC", RC2_CBC.OID });
		addReverseOID(CIPHER, "RC2_CBC", RC2_CBC.OID);
	}

	private void registerRC5() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, RC5KeyGenerator.class, RC5.ALG_NAME);
		add(SECRET_KEY_FACTORY, RC5KeyFactory.class, RC5.ALG_NAME);

		add(CIPHER, RC5.class, RC5.ALG_NAME);
	}

	private void registerRC6() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, RC6KeyGenerator.class, RC6.ALG_NAME);
		add(SECRET_KEY_FACTORY, RC6KeyFactory.class, RC6.ALG_NAME);

		add(CIPHER, RC6.class, RC6.ALG_NAME);
	}

	private void registerSAFERPlus() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, SAFERPlusKeyGenerator.class,
				SAFERPlus.ALG_NAME);
		add(SECRET_KEY_FACTORY, SAFERPlusKeyFactory.class, SAFERPlus.ALG_NAME);

		add(CIPHER, SAFERPlus.class, SAFERPlus.ALG_NAME);
	}

	private void registerSAFERPlusPlus() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, SAFERPlusPlusKeyGenerator.class,
				SAFERPlusPlus.ALG_NAME);
		add(SECRET_KEY_FACTORY, SAFERPlusPlusKeyFactory.class,
				SAFERPlusPlus.ALG_NAME);

		add(CIPHER, SAFERPlusPlus.class, SAFERPlusPlus.ALG_NAME);
	}

	private void registerSerpent() {
		add(SECRET_KEY_GENERATOR, SerpentKeyGenerator.class, new String[] {
				Serpent.ALG_NAME, Serpent.OID });
		add(SECRET_KEY_FACTORY, SerpentKeyFactory.class, new String[] {
				Serpent.ALG_NAME, Serpent.OID });

		add(CIPHER, Serpent.class,
				new String[] { Serpent.ALG_NAME, Serpent.OID });
		addReverseOID(CIPHER, Serpent.ALG_NAME, Serpent.OID);

		add(CIPHER, Serpent128_ECB.class, new String[] { "Serpent128_ECB",
				Serpent128_ECB.OID });
		addReverseOID(CIPHER, "Serpent128_ECB", Serpent128_ECB.OID);
		add(CIPHER, Serpent128_CBC.class, new String[] { "Serpent128_CBC",
				Serpent128_CBC.OID });
		addReverseOID(CIPHER, "Serpent128_CBC", Serpent128_CBC.OID);
		add(CIPHER, Serpent128_OFB.class, new String[] { "Serpent128_OFB",
				Serpent128_OFB.OID });
		addReverseOID(CIPHER, "Serpent128_OFB", Serpent128_OFB.OID);
		add(CIPHER, Serpent128_CFB.class, new String[] { "Serpent128_CFB",
				Serpent128_CFB.OID });
		addReverseOID(CIPHER, "Serpent128_CFB", Serpent128_CFB.OID);

		add(CIPHER, Serpent192_ECB.class, new String[] { "Serpent192_ECB",
				Serpent192_ECB.OID });
		addReverseOID(CIPHER, "Serpent192_ECB", Serpent192_ECB.OID);
		add(CIPHER, Serpent192_CBC.class, new String[] { "Serpent192_CBC",
				Serpent192_CBC.OID });
		addReverseOID(CIPHER, "Serpent192_CBC", Serpent192_CBC.OID);
		add(CIPHER, Serpent192_OFB.class, new String[] { "Serpent192_OFB",
				Serpent192_OFB.OID });
		addReverseOID(CIPHER, "Serpent192_OFB", Serpent192_OFB.OID);
		add(CIPHER, Serpent192_CFB.class, new String[] { "Serpent192_CFB",
				Serpent192_CFB.OID });
		addReverseOID(CIPHER, "Serpent192_CFB", Serpent192_CFB.OID);

		add(CIPHER, Serpent256_ECB.class, new String[] { "Serpent256_ECB",
				Serpent256_ECB.OID });
		addReverseOID(CIPHER, "Serpent256_ECB", Serpent256_ECB.OID);
		add(CIPHER, Serpent256_CBC.class, new String[] { "Serpent256_CBC",
				Serpent256_CBC.OID });
		addReverseOID(CIPHER, "Serpent256_CBC", Serpent256_CBC.OID);
		add(CIPHER, Serpent256_OFB.class, new String[] { "Serpent256_OFB",
				Serpent256_OFB.OID });
		addReverseOID(CIPHER, "Serpent256_OFB", Serpent256_OFB.OID);
		add(CIPHER, Serpent256_CFB.class, new String[] { "Serpent256_CFB",
				Serpent256_CFB.OID });
		addReverseOID(CIPHER, "Serpent256_CFB", Serpent256_CFB.OID);
	}

	private void registerShacal() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, ShacalKeyGenerator.class, Shacal.ALG_NAME);
		add(SECRET_KEY_FACTORY, ShacalKeyFactory.class, Shacal.ALG_NAME);

		add(CIPHER, Shacal.class, Shacal.ALG_NAME);
	}

	private void registerShacal2() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, Shacal2KeyGenerator.class, Shacal2.ALG_NAME);
		add(SECRET_KEY_FACTORY, Shacal2KeyFactory.class, Shacal2.ALG_NAME);

		add(CIPHER, Shacal2.class, Shacal2.ALG_NAME);
	}

	private void registerTwofish() {
		// TODO: OIDs
		add(SECRET_KEY_GENERATOR, TwofishKeyGenerator.class, Twofish.ALG_NAME);
		add(SECRET_KEY_FACTORY, TwofishKeyFactory.class, Twofish.ALG_NAME);

		add(CIPHER, Twofish.class, Twofish.ALG_NAME);
	}

	private void registerPBE() {
		/* common */

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

		add(ALG_PARAMS, PBEParameters.class, new String[] { "PBE", "PBES1",
				"PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID,
				"PbeWithSHA1AndDES_CBC", PBEWithSHA1AndDES_CBC.OID,
				"PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID,
				"PbeWithSHAAnd40BitRC2_CBC", PBEWithSHAAnd40BitRC2_CBC.OID });

		// PBE with MD5 and DES in CBC mode
		add(CIPHER, PBEWithMD5AndDES_CBC.class, new String[] {
				"PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID });
		addReverseOID(CIPHER, "PbeWithMD5AndDES_CBC", PBEWithMD5AndDES_CBC.OID);

		// PBE with SHA1 and DES in CBC mode
		add(CIPHER, PBEWithSHA1AndDES_CBC.class, new String[] {
				"PbeWithSHA1AndDES_CBC", PBEWithSHA1AndDES_CBC.OID });
		addReverseOID(CIPHER, "PbeWithSHA1AndDES_CBC",
				PBEWithSHA1AndDES_CBC.OID);

		// PBE with SHA1 and 3-key TripleDES in CBC mode for PKCS#12
		add(CIPHER, PBEWithSHAAnd3_KeyTripleDES_CBC.class, new String[] {
				"PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID });
		addReverseOID(CIPHER, "PbeWithSHAAnd3_KeyTripleDES_CBC",
				PBEWithSHAAnd3_KeyTripleDES_CBC.OID);

		// PBE with SHA1 and 40-bit RC2 in CBC mode for PKCS#12
		add(CIPHER, PBEWithSHAAnd40BitRC2_CBC.class, new String[] {
				"PbeWithSHAAnd40BitRC2_CBC", PBEWithSHAAnd40BitRC2_CBC.OID });
		addReverseOID(CIPHER, "PbeWithSHAAnd40BitRC2_CBC",
				PBEWithSHAAnd40BitRC2_CBC.OID);

		/* PBES2 */

		add(ALG_PARAMS, PBKDF2Parameters.class, new String[] { "PBKDF2",
				PBKDF2Parameters.OID });

		add(ALG_PARAMS, PBES2Parameters.class, new String[] { "PBES2",
				PBES2.OID });

		add(CIPHER, PBES2.class, new String[] { "PBES2", PBES2.OID });
		addReverseOID(CIPHER, "PBES2", PBES2.OID);
	}

	private void registerBBS() {
		add(SECURE_RANDOM, BBSRandom.class, new String[] { "BBS", "BBSRandom" });
	}

}
