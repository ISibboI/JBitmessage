package de.flexiprovider.nf;

import de.flexiprovider.api.Registry;
import de.flexiprovider.nf.iq.iqdsa.IQDSAKeyFactory;
import de.flexiprovider.nf.iq.iqdsa.IQDSAKeyPairGenerator;
import de.flexiprovider.nf.iq.iqdsa.IQDSAParamGenParameterSpec;
import de.flexiprovider.nf.iq.iqdsa.IQDSAParameterGenerator;
import de.flexiprovider.nf.iq.iqdsa.IQDSAParameterSpec;
import de.flexiprovider.nf.iq.iqdsa.IQDSAParameters;
import de.flexiprovider.nf.iq.iqdsa.IQDSASignature;
import de.flexiprovider.nf.iq.iqgq.IQGQKeyFactory;
import de.flexiprovider.nf.iq.iqgq.IQGQKeyPairGenerator;
import de.flexiprovider.nf.iq.iqgq.IQGQParamGenParameterSpec;
import de.flexiprovider.nf.iq.iqgq.IQGQParameterGenerator;
import de.flexiprovider.nf.iq.iqgq.IQGQParameterSpec;
import de.flexiprovider.nf.iq.iqgq.IQGQParameters;
import de.flexiprovider.nf.iq.iqgq.IQGQSignature;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAKeyFactory;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAKeyPairGenerator;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAParamGenParameterSpec;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAParameterGenerator;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAParameterSpec;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAParameters;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSASignature;

/**
 * Register all algorithms of the <a href="package.html">NF package</a>.
 */
public abstract class NFRegistry extends Registry {

	// flag indicating if algorithms already have been registered
	private static boolean registered;

	/**
	 * Register all algorithms of the <a href="package.html">NF package</a>.
	 */
	public static void registerAlgorithms() {
		if (!registered) {
			registerIQDSA();
			registerIQGQ();
			registerIQRDSA();
			registered = true;
		}
	}

	private static void registerIQDSA() {
		add(ALG_PARAM_SPEC, IQDSAParamGenParameterSpec.class, new String[] {
				"IQDSAParamGen", IQDSAKeyFactory.OID });
		add(ALG_PARAM_GENERATOR, IQDSAParameterGenerator.class, new String[] {
				"IQDSA", IQDSAKeyFactory.OID });

		add(ALG_PARAM_SPEC, IQDSAParameterSpec.class, new String[] { "IQDSA",
				IQDSAKeyFactory.OID });
		add(ALG_PARAMS, IQDSAParameters.class, new String[] { "IQDSA",
				IQDSAKeyFactory.OID });

		add(KEY_PAIR_GENERATOR, IQDSAKeyPairGenerator.class, new String[] {
				"IQDSA", IQDSAKeyFactory.OID });
		add(KEY_FACTORY, IQDSAKeyFactory.class, new String[] { "IQDSA",
				IQDSAKeyFactory.OID });

		add(SIGNATURE, IQDSASignature.SHA1.class, new String[] {
				"SHA1withIQDSA", "IQDSA", IQDSASignature.SHA1.OID });
		add(SIGNATURE, IQDSASignature.RIPEMD160.class, new String[] {
				"RIPEMD160withIQDSA", IQDSASignature.RIPEMD160.OID });
	}

	private static void registerIQGQ() {
		add(ALG_PARAM_SPEC, IQGQParamGenParameterSpec.class, new String[] {
				"IQGQParamGen", IQGQKeyFactory.OID });
		add(ALG_PARAM_GENERATOR, IQGQParameterGenerator.class, new String[] {
				"IQGQ", IQGQKeyFactory.OID });

		add(ALG_PARAM_SPEC, IQGQParameterSpec.class, new String[] { "IQGQ",
				IQGQKeyFactory.OID });
		add(ALG_PARAMS, IQGQParameters.class, new String[] { "IQGQ",
				IQGQKeyFactory.OID });

		add(KEY_PAIR_GENERATOR, IQGQKeyPairGenerator.class, new String[] {
				"IQGQ", IQGQKeyFactory.OID });
		add(KEY_FACTORY, IQGQKeyFactory.class, new String[] { "IQGQ",
				IQGQKeyFactory.OID });

		add(SIGNATURE, IQGQSignature.SHA1.class, new String[] { "SHA1withIQGQ",
				"IQGQ", IQGQSignature.SHA1.OID });
		add(SIGNATURE, IQGQSignature.RIPEMD160.class, new String[] {
				"RIPEMD160withIQGQ", IQGQSignature.RIPEMD160.OID });
	}

	private static void registerIQRDSA() {
		add(ALG_PARAM_SPEC, IQRDSAParamGenParameterSpec.class, new String[] {
				"IQRDSAParamGen", IQRDSAKeyFactory.OID });
		add(ALG_PARAM_GENERATOR, IQRDSAParameterGenerator.class, new String[] {
				"IQRDSA", IQRDSAKeyFactory.OID });

		add(ALG_PARAM_SPEC, IQRDSAParameterSpec.class, new String[] { "IQRDSA",
				IQRDSAKeyFactory.OID });
		add(ALG_PARAMS, IQRDSAParameters.class, new String[] { "IQRDSA",
				IQRDSAKeyFactory.OID });

		add(KEY_PAIR_GENERATOR, IQRDSAKeyPairGenerator.class, new String[] {
				"IQRDSA", IQRDSAKeyFactory.OID });
		add(KEY_FACTORY, IQRDSAKeyFactory.class, new String[] { "IQRDSA",
				IQRDSAKeyFactory.OID });

		add(SIGNATURE, IQRDSASignature.SHA1.class, new String[] {
				"SHA1withIQRDSA", "IQRDSA", IQRDSASignature.SHA1.OID });
		add(SIGNATURE, IQRDSASignature.RIPEMD160.class, new String[] {
				"RIPEMD160withIQRDSA", IQRDSASignature.RIPEMD160.OID });
	}

}
