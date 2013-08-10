package de.flexiprovider.nf;

import de.flexiprovider.api.FlexiProvider;
import de.flexiprovider.nf.iq.iqdsa.IQDSAKeyFactory;
import de.flexiprovider.nf.iq.iqdsa.IQDSAKeyPairGenerator;
import de.flexiprovider.nf.iq.iqdsa.IQDSAParameterGenerator;
import de.flexiprovider.nf.iq.iqdsa.IQDSAParameters;
import de.flexiprovider.nf.iq.iqdsa.IQDSASignature;
import de.flexiprovider.nf.iq.iqgq.IQGQKeyFactory;
import de.flexiprovider.nf.iq.iqgq.IQGQKeyPairGenerator;
import de.flexiprovider.nf.iq.iqgq.IQGQParameterGenerator;
import de.flexiprovider.nf.iq.iqgq.IQGQParameters;
import de.flexiprovider.nf.iq.iqgq.IQGQSignature;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAKeyFactory;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAKeyPairGenerator;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAParameterGenerator;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSAParameters;
import de.flexiprovider.nf.iq.iqrdsa.IQRDSASignature;

/**
 * A JCA/JCE provider for cryptographic algorithms in class groups of imaginary
 * quadratic number fields.
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
 * import de.flexiprovider.nf.FlexiNFProvider;
 * 
 * Security.addProvider(new FlexiNFProvider());
 * </pre>
 * 
 * The provider is registered statically by adding an entry to the
 * <tt>java.security</tt> properties file (usually
 * <tt>$JAVA_HOME/lib/security/java.security</tt>). See that file for
 * instructions.
 * 
 * <h4>Contents of the FlexiNFProvider</h4>
 * 
 * <ul type=circle>
 * 
 * <li>Digital signatures:
 * <ul type = square>
 * <li><a href = iq/iqrdsa/IQRDSASignature.html>Signature.IQRDSA</a></li>
 * <li><a href = iq/iqdsa/IQDSASignature.html>Signature.IQDSA</a></li>
 * <li><a href = iq/iqgq/IQGQSignature.html>Signature.IQGQ</a></li>
 * </ul>
 * 
 * </ul>
 * 
 * @author <a href="mailto:info@flexiprovider.de">FlexiProvider group</a>.
 * @version 1.7.6
 */
public class FlexiNFProvider extends FlexiProvider {

    private static final String INFO = "IQRDSA, IQDSA, IQGQ using SHA-1";

    /**
     * Constructor. Register all algorithms for FlexiAPI and JCA.
     */
    public FlexiNFProvider() {
	super("FlexiNF", 1.76, INFO);

	// ------------------------------------------------
	// register algorithms for FlexiAPI
	// ------------------------------------------------

	NFRegistry.registerAlgorithms();

	// ------------------------------------------------
	// register algorithms for JCA/JCE
	// ------------------------------------------------

	registerIQDSA();
	registerIQGQ();
	registerIQRDSA();
    }

    private void registerIQDSA() {
	add(ALG_PARAM_GENERATOR, IQDSAParameterGenerator.class, new String[] {
		"IQDSA", IQDSAKeyFactory.OID });
	addReverseOID(ALG_PARAM_GENERATOR, "IQDSA", IQDSAKeyFactory.OID);

	add(ALG_PARAMS, IQDSAParameters.class, new String[] { "IQDSA",
		IQDSAKeyFactory.OID });
	addReverseOID(ALG_PARAMS, "IQDSA", IQDSAKeyFactory.OID);

	add(KEY_PAIR_GENERATOR, IQDSAKeyPairGenerator.class, new String[] {
		"IQDSA", IQDSAKeyFactory.OID });
	addReverseOID(KEY_PAIR_GENERATOR, "IQDSA", IQDSAKeyFactory.OID);

	add(KEY_FACTORY, IQDSAKeyFactory.class, new String[] { "IQDSA",
		IQDSAKeyFactory.OID });
	addReverseOID(KEY_FACTORY, "IQDSA", IQDSAKeyFactory.OID);

	add(SIGNATURE, IQDSASignature.SHA1.class, new String[] {
		"SHA1withIQDSA", "IQDSA", IQDSASignature.SHA1.OID });
	addReverseOID(SIGNATURE, "SHA1withIQDSA", IQDSASignature.SHA1.OID);
	add(SIGNATURE, IQDSASignature.RIPEMD160.class, new String[] {
		"RIPEMD160withIQDSA", IQDSASignature.RIPEMD160.OID });
	addReverseOID(SIGNATURE, "RIPEMD160withIQDSA",
		IQDSASignature.RIPEMD160.OID);
    }

    private void registerIQGQ() {
	add(ALG_PARAM_GENERATOR, IQGQParameterGenerator.class, new String[] {
		"IQGQ", IQGQKeyFactory.OID });
	addReverseOID(ALG_PARAM_GENERATOR, "IQGQ", IQGQKeyFactory.OID);

	add(ALG_PARAMS, IQGQParameters.class, new String[] { "IQGQ",
		IQGQKeyFactory.OID });
	addReverseOID(ALG_PARAMS, "IQGQ", IQGQKeyFactory.OID);

	add(KEY_PAIR_GENERATOR, IQGQKeyPairGenerator.class, new String[] {
		"IQGQ", IQGQKeyFactory.OID });
	addReverseOID(KEY_PAIR_GENERATOR, "IQGQ", IQGQKeyFactory.OID);

	add(KEY_FACTORY, IQGQKeyFactory.class, new String[] { "IQGQ",
		IQGQKeyFactory.OID });
	addReverseOID(KEY_FACTORY, "IQGQ", IQGQKeyFactory.OID);

	add(SIGNATURE, IQGQSignature.SHA1.class, new String[] { "SHA1withIQGQ",
		"IQGQ", IQGQSignature.SHA1.OID });
	addReverseOID(SIGNATURE, "SHA1withIQGQ", IQGQSignature.SHA1.OID);
	add(SIGNATURE, IQGQSignature.RIPEMD160.class, new String[] {
		"RIPEMD160withIQGQ", IQGQSignature.RIPEMD160.OID });
	addReverseOID(SIGNATURE, "RIPEMD160withIQGQ",
		IQGQSignature.RIPEMD160.OID);
    }

    private void registerIQRDSA() {
	add(ALG_PARAM_GENERATOR, IQRDSAParameterGenerator.class, new String[] {
		"IQRDSA", IQRDSAKeyFactory.OID });
	addReverseOID(ALG_PARAM_GENERATOR, "IQRDSA", IQRDSAKeyFactory.OID);

	add(ALG_PARAMS, IQRDSAParameters.class, new String[] { "IQRDSA",
		IQRDSAKeyFactory.OID });
	addReverseOID(ALG_PARAMS, "IQRDSA", IQRDSAKeyFactory.OID);

	add(KEY_PAIR_GENERATOR, IQRDSAKeyPairGenerator.class, new String[] {
		"IQRDSA", IQRDSAKeyFactory.OID });
	addReverseOID(KEY_PAIR_GENERATOR, "IQRDSA", IQRDSAKeyFactory.OID);

	add(KEY_FACTORY, IQRDSAKeyFactory.class, new String[] { "IQRDSA",
		IQRDSAKeyFactory.OID });
	addReverseOID(KEY_FACTORY, "IQRDSA", IQRDSAKeyFactory.OID);

	add(SIGNATURE, IQRDSASignature.SHA1.class, new String[] {
		"SHA1withIQRDSA", "IQRDSA", IQRDSASignature.SHA1.OID });
	addReverseOID(SIGNATURE, "SHA1withIQRDSA", IQRDSASignature.SHA1.OID);
	add(SIGNATURE, IQRDSASignature.RIPEMD160.class, new String[] {
		"RIPEMD160withIQRDSA", IQRDSASignature.RIPEMD160.OID });
	addReverseOID(SIGNATURE, "RIPEMD160withIQRDSA",
		IQRDSASignature.RIPEMD160.OID);
    }

}
