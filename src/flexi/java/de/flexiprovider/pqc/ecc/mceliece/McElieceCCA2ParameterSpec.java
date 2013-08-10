package de.flexiprovider.pqc.ecc.mceliece;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class provides a specification for the parameters of the CCA2-secure
 * variants of the McEliece PKCS that are used with
 * {@link McElieceFujisakiCipher}, {@link McElieceKobaraImaiCipher}, and
 * {@link McEliecePointchevalCipher}.
 * 
 * @see McElieceFujisakiCipher
 * @see McElieceKobaraImaiCipher
 * @see McEliecePointchevalCipher
 * @author Elena Klintsevich
 * @author Martin Döring
 */
public class McElieceCCA2ParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default message digest ("SHA256").
     */
    public static final String DEFAULT_MD = "SHA256";

    private String mdName;

    /**
     * Construct the default parameters. Choose the
     */
    public McElieceCCA2ParameterSpec() {
	this(DEFAULT_MD);
    }

    /**
     * Constructor.
     * 
     * @param mdName
     *                the name of the hash function
     */
    public McElieceCCA2ParameterSpec(String mdName) {
	// check whether message digest is available
	try {
	    Registry.getMessageDigest(mdName);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new InvalidParameterException("Message digest '" + mdName
		    + "' not found'.");
	}

	// assign message digest name
	this.mdName = mdName;
    }

    /**
     * @return the name of the hash function
     */
    public String getMDName() {
	return mdName;
    }

}
