package de.flexiprovider.ec;

import de.flexiprovider.api.Registry;
import de.flexiprovider.common.ies.IESParameterSpec;
import de.flexiprovider.ec.keys.ECKeyFactory;
import de.flexiprovider.ec.keys.ECKeyPairGenerator;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.ec.parameters.ECParameters;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP160r1;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP192r1;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP224r1;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP256r1;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP320r1;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP384r1;
import de.flexiprovider.ec.parameters.CurveRegistry.BrainpoolP512r1;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime192v1;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime192v2;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime192v3;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime239v1;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime239v2;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime239v3;
import de.flexiprovider.ec.parameters.CurveRegistry.Prime256v1;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve1;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve10;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve11;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve12;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve13;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve14;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve15;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve16;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve17;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve18;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve19;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve2;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve20;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve21;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve22;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve23;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve24;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve25;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve26;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve27;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve28;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve29;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve3;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve30;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve31;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve32;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve33;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve34;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve35;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve36;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve37;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve38;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve4;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve5;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve6;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve7;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve8;
import de.flexiprovider.ec.parameters.CurveRegistry.PrimeCurve9;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp112r1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp112r2;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp128r1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp128r2;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp160k1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp160r1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp160r2;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp192k1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp224k1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp224r1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp256k1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp384r1;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp521r1;

/**
 * Register all algorithms of the <a href="package.html">EC package</a>.
 */
public abstract class ECRegistry extends Registry {

	// flag indicating if algorithms already have been registered
	private static boolean registered = false;

	/**
	 * Register all algorithms of the <a href="package.html">EC package</a>.
	 */
	public static void registerAlgorithms() {
		if (!registered) {
			registerCommon();
			registerECDSA();
			registerECNR();
			registerECIES();
			registerECSVDPDH();
			registerECPRNG();
			registered = true;
		}
	}

	private static void registerCommon() {
		add(KEY_PAIR_GENERATOR, ECKeyPairGenerator.class, new String[] { "EC",
				"ECDSA", "ECNR", "ECDH", "ECIES", ECKeyFactory.OID });

		add(KEY_FACTORY, ECKeyFactory.class, new String[] { "EC", "ECDSA",
				"ECNR", "ECDH", "ECIES", ECKeyFactory.OID });

		add(ALG_PARAM_SPEC, CurveParams.class, new String[] { "EC",
				ECParameters.OID, ECKeyFactory.OID, "ECDSA", "SHA1withECDSA",
				"SHA1/ECDSA", ECDSASignature.SHA1.OID, "SHA224withECDSA",
				"SHA224/ECDSA", ECDSASignature.SHA224.OID, "SHA256withECDSA",
				"SHA256/ECDSA", ECDSASignature.SHA256.OID, "SHA384withECDSA",
				"SHA384/ECDSA", ECDSASignature.SHA384.OID, "SHA512withECDSA",
				"SHA512/ECDSA", ECDSASignature.SHA512.OID, "RawECDSA",
				"RAWECDSA", "ECNR", "SHA1withECNR", "SHA1/ECNR", "ECDH" });

		add(ALG_PARAMS, ECParameters.class, new String[] { "EC",
				ECParameters.OID, ECKeyFactory.OID, "ECDSA", "SHA1withECDSA",
				"SHA1/ECDSA", ECDSASignature.SHA1.OID, "SHA224withECDSA",
				"SHA224/ECDSA", ECDSASignature.SHA224.OID, "SHA256withECDSA",
				"SHA256/ECDSA", ECDSASignature.SHA256.OID, "SHA384withECDSA",
				"SHA384/ECDSA", ECDSASignature.SHA384.OID, "SHA512withECDSA",
				"SHA512/ECDSA", ECDSASignature.SHA512.OID, "RawECDSA",
				"RAWECDSA", "ECNR", "SHA1withECNR", "SHA1/ECNR", "ECDH" });

		/* Curves over GF(p) */

		// ANSI X9.62
		add(ALG_PARAM_SPEC, Prime192v1.class, new String[] { "prime192v1",
				Prime192v1.OID });
		add(ALG_PARAM_SPEC, Prime192v2.class, new String[] { "prime192v2",
				Prime192v2.OID });
		add(ALG_PARAM_SPEC, Prime192v3.class, new String[] { "prime192v3",
				Prime192v3.OID });
		add(ALG_PARAM_SPEC, Prime239v1.class, new String[] { "prime239v1",
				Prime239v1.OID });
		add(ALG_PARAM_SPEC, Prime239v2.class, new String[] { "prime239v2",
				Prime239v2.OID });
		add(ALG_PARAM_SPEC, Prime239v3.class, new String[] { "prime239v3",
				Prime239v3.OID });
		add(ALG_PARAM_SPEC, Prime256v1.class, new String[] { "prime256v1",
				Prime256v1.OID });

		// SEC 2
		add(ALG_PARAM_SPEC, Secp112r1.class, new String[] { "secp112r1",
				Secp112r1.OID });
		add(ALG_PARAM_SPEC, Secp112r2.class, new String[] { "secp112r2",
				Secp112r2.OID });
		add(ALG_PARAM_SPEC, Secp128r1.class, new String[] { "secp128r1",
				Secp128r1.OID });
		add(ALG_PARAM_SPEC, Secp128r2.class, new String[] { "secp128r2",
				Secp128r2.OID });
		add(ALG_PARAM_SPEC, Secp160k1.class, new String[] { "secp160k1",
				Secp160k1.OID });
		add(ALG_PARAM_SPEC, Secp160r1.class, new String[] { "secp160r1",
				Secp160r1.OID });
		add(ALG_PARAM_SPEC, Secp160r2.class, new String[] { "secp160r2",
				Secp160r2.OID });
		add(ALG_PARAM_SPEC, Secp192k1.class, new String[] { "secp192k1",
				Secp192k1.OID });
		add(ALG_PARAM_SPEC, Secp224k1.class, new String[] { "secp224k1",
				Secp224k1.OID });
		add(ALG_PARAM_SPEC, Secp224r1.class, new String[] { "secp224r1",
				Secp224r1.OID });
		add(ALG_PARAM_SPEC, Secp256k1.class, new String[] { "secp256k1",
				Secp256k1.OID });
		add(ALG_PARAM_SPEC, Secp384r1.class, new String[] { "secp384r1",
				Secp384r1.OID });
		add(ALG_PARAM_SPEC, Secp521r1.class, new String[] { "secp521r1",
				Secp521r1.OID });

		// ECC brainpool
		add(ALG_PARAM_SPEC, BrainpoolP160r1.class, new String[] {
				"brainpoolP160r1", BrainpoolP160r1.OID });
		add(ALG_PARAM_SPEC, BrainpoolP192r1.class, new String[] {
				"brainpoolP192r1", BrainpoolP192r1.OID });
		add(ALG_PARAM_SPEC, BrainpoolP224r1.class, new String[] {
				"brainpoolP224r1", BrainpoolP224r1.OID });
		add(ALG_PARAM_SPEC, BrainpoolP256r1.class, new String[] {
				"brainpoolP256r1", BrainpoolP256r1.OID });
		add(ALG_PARAM_SPEC, BrainpoolP320r1.class, new String[] {
				"brainpoolP320r1", BrainpoolP320r1.OID });
		add(ALG_PARAM_SPEC, BrainpoolP384r1.class, new String[] {
				"brainpoolP384r1", BrainpoolP384r1.OID });
		add(ALG_PARAM_SPEC, BrainpoolP512r1.class, new String[] {
				"brainpoolP512r1", BrainpoolP512r1.OID });

		// CDC
		add(ALG_PARAM_SPEC, PrimeCurve1.class, new String[] { "primeCurve1",
				PrimeCurve1.OID });
		add(ALG_PARAM_SPEC, PrimeCurve2.class, new String[] { "primeCurve2",
				PrimeCurve2.OID });
		add(ALG_PARAM_SPEC, PrimeCurve3.class, new String[] { "primeCurve3",
				PrimeCurve3.OID });
		add(ALG_PARAM_SPEC, PrimeCurve4.class, new String[] { "primeCurve4",
				PrimeCurve4.OID });
		add(ALG_PARAM_SPEC, PrimeCurve5.class, new String[] { "primeCurve5",
				PrimeCurve5.OID });
		add(ALG_PARAM_SPEC, PrimeCurve6.class, new String[] { "primeCurve6",
				PrimeCurve6.OID });
		add(ALG_PARAM_SPEC, PrimeCurve7.class, new String[] { "primeCurve7",
				PrimeCurve7.OID });
		add(ALG_PARAM_SPEC, PrimeCurve8.class, new String[] { "primeCurve8",
				PrimeCurve8.OID });
		add(ALG_PARAM_SPEC, PrimeCurve9.class, new String[] { "primeCurve9",
				PrimeCurve9.OID });
		add(ALG_PARAM_SPEC, PrimeCurve10.class, new String[] { "primeCurve10",
				PrimeCurve10.OID });
		add(ALG_PARAM_SPEC, PrimeCurve11.class, new String[] { "primeCurve11",
				PrimeCurve11.OID });
		add(ALG_PARAM_SPEC, PrimeCurve12.class, new String[] { "primeCurve12",
				PrimeCurve12.OID });
		add(ALG_PARAM_SPEC, PrimeCurve13.class, new String[] { "primeCurve13",
				PrimeCurve13.OID });
		add(ALG_PARAM_SPEC, PrimeCurve14.class, new String[] { "primeCurve14",
				PrimeCurve14.OID });
		add(ALG_PARAM_SPEC, PrimeCurve15.class, new String[] { "primeCurve15",
				PrimeCurve15.OID });
		add(ALG_PARAM_SPEC, PrimeCurve16.class, new String[] { "primeCurve16",
				PrimeCurve16.OID });
		add(ALG_PARAM_SPEC, PrimeCurve17.class, new String[] { "primeCurve17",
				PrimeCurve17.OID });
		add(ALG_PARAM_SPEC, PrimeCurve18.class, new String[] { "primeCurve18",
				PrimeCurve18.OID });
		add(ALG_PARAM_SPEC, PrimeCurve19.class, new String[] { "primeCurve19",
				PrimeCurve19.OID });
		add(ALG_PARAM_SPEC, PrimeCurve20.class, new String[] { "primeCurve20",
				PrimeCurve20.OID });
		add(ALG_PARAM_SPEC, PrimeCurve21.class, new String[] { "primeCurve21",
				PrimeCurve21.OID });
		add(ALG_PARAM_SPEC, PrimeCurve22.class, new String[] { "primeCurve22",
				PrimeCurve22.OID });
		add(ALG_PARAM_SPEC, PrimeCurve23.class, new String[] { "primeCurve23",
				PrimeCurve23.OID });
		add(ALG_PARAM_SPEC, PrimeCurve24.class, new String[] { "primeCurve24",
				PrimeCurve24.OID });
		add(ALG_PARAM_SPEC, PrimeCurve25.class, new String[] { "primeCurve25",
				PrimeCurve25.OID });
		add(ALG_PARAM_SPEC, PrimeCurve26.class, new String[] { "primeCurve26",
				PrimeCurve26.OID });
		add(ALG_PARAM_SPEC, PrimeCurve27.class, new String[] { "primeCurve27",
				PrimeCurve27.OID });
		add(ALG_PARAM_SPEC, PrimeCurve28.class, new String[] { "primeCurve28",
				PrimeCurve28.OID });
		add(ALG_PARAM_SPEC, PrimeCurve29.class, new String[] { "primeCurve29",
				PrimeCurve29.OID });
		add(ALG_PARAM_SPEC, PrimeCurve30.class, new String[] { "primeCurve30",
				PrimeCurve30.OID });
		add(ALG_PARAM_SPEC, PrimeCurve31.class, new String[] { "primeCurve31",
				PrimeCurve31.OID });
		add(ALG_PARAM_SPEC, PrimeCurve32.class, new String[] { "primeCurve32",
				PrimeCurve32.OID });
		add(ALG_PARAM_SPEC, PrimeCurve33.class, new String[] { "primeCurve33",
				PrimeCurve33.OID });
		add(ALG_PARAM_SPEC, PrimeCurve34.class, new String[] { "primeCurve34",
				PrimeCurve34.OID });
		add(ALG_PARAM_SPEC, PrimeCurve35.class, new String[] { "primeCurve35",
				PrimeCurve35.OID });
		add(ALG_PARAM_SPEC, PrimeCurve36.class, new String[] { "primeCurve36",
				PrimeCurve36.OID });
		add(ALG_PARAM_SPEC, PrimeCurve37.class, new String[] { "primeCurve37",
				PrimeCurve37.OID });
		add(ALG_PARAM_SPEC, PrimeCurve38.class, new String[] { "primeCurve38",
				PrimeCurve38.OID });

		addStandardAlgParams(new String[] { "EC", ECKeyFactory.OID, "ECDSA",
				"SHA1withECDSA", "SHA1/ECDSA", ECDSASignature.SHA1.OID,
				"SHA224withECDSA", "SHA224/ECDSA", ECDSASignature.SHA224.OID,
				"SHA256withECDSA", "SHA256/ECDSA", ECDSASignature.SHA256.OID,
				"SHA384withECDSA", "SHA384/ECDSA", ECDSASignature.SHA384.OID,
				"SHA512withECDSA", "SHA512/ECDSA", ECDSASignature.SHA512.OID,
				"RawECDSA", "RAWECDSA", "ECNR", "SHA1withECNR", "SHA1/ECNR",
				"ECDH" },

		new String[] {/* Curves over GF(p) */

				// ANSI X9.62
				Prime192v1.OID,
				Prime192v2.OID,
				Prime192v3.OID,
				Prime239v1.OID,
				Prime239v2.OID,
				Prime239v3.OID,
				Prime256v1.OID,

				// SEC 2
				Secp112r1.OID,
				Secp112r2.OID,
				Secp128r1.OID,
				Secp128r2.OID,
				Secp160k1.OID,
				Secp160r1.OID,
				Secp160r2.OID,
				Secp192k1.OID,
				Secp224k1.OID,
				Secp224r1.OID,
				Secp256k1.OID,
				Secp384r1.OID,

				// ECC brainpool
				BrainpoolP160r1.OID,
				BrainpoolP192r1.OID,
				BrainpoolP224r1.OID,
				BrainpoolP256r1.OID,
				BrainpoolP320r1.OID,
				BrainpoolP384r1.OID,
				BrainpoolP512r1.OID,

				// CDC
				PrimeCurve1.OID, PrimeCurve2.OID, PrimeCurve3.OID,
				PrimeCurve4.OID, PrimeCurve5.OID, PrimeCurve6.OID,
				PrimeCurve7.OID, PrimeCurve8.OID, PrimeCurve9.OID,
				PrimeCurve10.OID, PrimeCurve11.OID, PrimeCurve12.OID,
				PrimeCurve13.OID, PrimeCurve14.OID, PrimeCurve15.OID,
				PrimeCurve16.OID, PrimeCurve17.OID, PrimeCurve18.OID,
				PrimeCurve19.OID, PrimeCurve20.OID, PrimeCurve21.OID,
				PrimeCurve22.OID, PrimeCurve23.OID, PrimeCurve24.OID,
				PrimeCurve25.OID, PrimeCurve26.OID, PrimeCurve27.OID,
				PrimeCurve28.OID, PrimeCurve29.OID, PrimeCurve30.OID,
				PrimeCurve31.OID, PrimeCurve32.OID, PrimeCurve33.OID,
				PrimeCurve34.OID, PrimeCurve35.OID, PrimeCurve36.OID,
				PrimeCurve37.OID, PrimeCurve38.OID });
	}

	private static void registerECDSA() {
		add(SIGNATURE, ECDSASignature.SHA1.class,
				new String[] { "SHA1withECDSA", "ECDSA", "SHA1/ECDSA",
						ECDSASignature.SHA1.OID });
		add(SIGNATURE, ECDSASignature.SHA224.class, new String[] {
				"SHA224withECDSA", "SHA224/ECDSA", ECDSASignature.SHA224.OID });
		add(SIGNATURE, ECDSASignature.SHA256.class, new String[] {
				"SHA256withECDSA", "SHA256/ECDSA", ECDSASignature.SHA256.OID });
		add(SIGNATURE, ECDSASignature.SHA384.class, new String[] {
				"SHA384withECDSA", "SHA384/ECDSA", ECDSASignature.SHA384.OID });
		add(SIGNATURE, ECDSASignature.SHA512.class, new String[] {
				"SHA512withECDSA", "SHA512/ECDSA", ECDSASignature.SHA512.OID });
		add(SIGNATURE, ECDSASignature.Raw.class, new String[] { "RawECDSA",
				"RAWECDSA" });
	}

	private static void registerECNR() {
		add(SIGNATURE, ECNRSignature.class, new String[] { "ECNR",
				"SHA1withECNR", "SHA1/ECNR" });
	}

	private static void registerECIES() {
		add(ALG_PARAM_SPEC, IESParameterSpec.class, new String[] { "IES",
				"ECIES" });

		add(ASYMMETRIC_HYBRID_CIPHER, ECIES.class, "ECIES");
	}

	private static void registerECSVDPDH() {
		add(KEY_AGREEMENT, ECSVDPDH.class, "ECSVDPDH");
		add(KEY_AGREEMENT, ECSVDPDHC.class, new String[] { "EC", "ECDH",
				"ECSVDPDHC" });
	}

	private static void registerECPRNG() {
		add(SECURE_RANDOM, ECPRNG.class, "ECPRNG");
	}

}
