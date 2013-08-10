package de.flexiprovider.pqc.ecc.niederreiter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.GoppaCode;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.math.linearalgebra.GF2Vector;
import de.flexiprovider.common.math.linearalgebra.Permutation;
import de.flexiprovider.common.util.BigEndianConversions;
import de.flexiprovider.core.md.RIPEMD160;
import de.flexiprovider.pqc.ecc.Conversions;

/**
 * This class implements the NiederreiterCFS signature scheme (N. Courtois, M.
 * Finiasz, N. Sendrier, "How to achieve a McEliece-based Digital Signature
 * Scheme", in Advances in Cryptology - ASIACRYPT 2001, vol. 2248, pp. 157-174).
 * <p>
 * The NiederreiterCFSSignature can be used as follows:
 * <p>
 * <b>Signature generation:</b>
 * <ol>
 * <li> generate KeySpec from encoded Niederreiter private key:<br/>
 * <tt>KeySpec privateKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);</tt></li>
 * <li>get instance of Niederreiter key factory:<br/>
 * <tt>KeyFactory keyFactory = KeyFactory.getInstance("Niederreiter","FlexiPQC");</tt></li>
 * <li>decode NiederreiterCFS private key:<br/>
 * <tt>PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);</tt></li>
 * <li>get instance of a NiederreiterCFS signature:<br/>
 * <tt>Signature cfsSig =
 * Signature.getInstance("NiederreiterCFSSignature","FlexiPQC");</tt></li>
 * <li>initialize signing:<br/> <tt>cfsSig.initSign(privateKey);</tt></li>
 * <li>sign message:<br/> <tt>cfsSig.update(message.getBytes());<br/>
 * signature = cfsSig.sign();<br/>
 * return signature;</tt></li>
 * </ol>
 * <p>
 * <b>Signature verification:</b>
 * <ol>
 * <li>generate KeySpec from encoded Niederreiter public key:<br/>
 * <tt>KeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);</tt></li>
 * <li>decode Niederreiter public key:<br/>
 * <tt>PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);</tt></li>
 * <li>initialize verifying:<br/> <tt>cfsSig.initVerify(publicKey);</tt></li>
 * <li>Verify the signature:<br/> <tt>cfsSig.update(message.getBytes());<br/>
 * return cfsSig.verify(signature);</tt></li>
 * </ol>
 * 
 * @author Elena Klintsevich
 */
public class NiederreiterCFSSignature extends Signature {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = NiederreiterKeyFactory.OID + ".2";

    // the private key
    private NiederreiterPrivateKey privKey;

    // the public key
    private NiederreiterPublicKey pubKey;

    // the check matrix
    private GF2Matrix h;

    // the hash function of the NiederreiterCFS signature
    private MessageDigest md;

    // the ByteArrayOutputStream used to store the message
    private ByteArrayOutputStream baos;

    /**
     * Constructor. Choose the default message digest ({@link RIPEMD160}).
     */
    public NiederreiterCFSSignature() {
	md = new RIPEMD160();
    }

    /**
     * Initialize the signature algorithm for signing a message.
     * 
     * @param key
     *                the private key of the signer
     * @param random
     *                a source of randomness (not used)
     * @throws InvalidKeyException
     *                 if the key is not an instance of
     *                 {@link NiederreiterPrivateKey}.
     */
    public void initSign(PrivateKey key, SecureRandom random)
	    throws InvalidKeyException {
	if (!(key instanceof NiederreiterPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	privKey = (NiederreiterPrivateKey) key;

	h = GoppaCode.createCanonicalCheckMatrix(privKey.getField(), privKey
		.getGoppaPoly());
	baos = new ByteArrayOutputStream();
    }

    /**
     * Initialize the signature algorithm for verifying a signature.
     * 
     * @param key
     *                the public key of the signer
     * @throws InvalidKeyException
     *                 if the public key is not an instance of
     *                 NiederreiterPublicKey.
     */
    public void initVerify(PublicKey key) throws InvalidKeyException {
	if (!(key instanceof NiederreiterPublicKey)) {
	    throw new InvalidKeyException("Key is not a NiederreiterPublicKey.");
	}
	pubKey = (NiederreiterPublicKey) key;
	baos = new ByteArrayOutputStream();
    }

    /**
     * Set parameters for the this signature. As the parameters are contained in
     * the keys, this method is not implemented.
     * 
     * @param params
     *                the parameters (not used)
     */
    public void setParameters(AlgorithmParameterSpec params) {
	// empty
    }

    /**
     * Feed a message byte to the message digest.
     * 
     * @param data
     *                array of message bytes
     */
    public void update(byte data) {
	baos.write(data);
    }

    /**
     * Feed message bytes to the message digest.
     * 
     * @param data
     *                array of message bytes
     * @param off
     *                index of message start
     * @param length
     *                number of message bytes
     */
    public void update(byte[] data, int off, int length) {
	baos.write(data, off, length);
    }

    /**
     * Sign a message.
     * 
     * @return the signature
     */
    public byte[] sign() {
	int k = privKey.getK();
	int m = privKey.getM();
	int n = 1 << m;
	int t = privKey.getT();
	GF2mField field = privKey.getField();
	PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
	GF2Matrix matrixS = privKey.getSInv();
	Permutation p = privKey.getP();
	PolynomialGF2mSmallM[] sqRootMatrix = privKey.getQInv();

	int q = k >>> 3;
	int r = Math.min(q, md.getDigestLength());
	if ((k & 7) != 0) {
	    q++;
	}

	byte[] data = md.digest(getData());

	byte[] pad = new byte[8];
	byte[] help, dt;
	long ind = 0;

	GF2Vector vec, s0, s1;
	do {
	    pad = BigEndianConversions.I2OSP(ind);

	    help = new byte[data.length + 8];
	    System.arraycopy(data, 0, help, 0, data.length);
	    System.arraycopy(pad, 0, help, data.length, 8);

	    help = md.digest(help);

	    dt = new byte[q];
	    System.arraycopy(help, 0, dt, 0, r);

	    vec = GF2Vector.OS2VP(k, dt);
	    s0 = (GF2Vector) matrixS.rightMultiply(vec);
	    vec = GoppaCode.syndromeDecode(s0, field, gp, sqRootMatrix);
	    s1 = (GF2Vector) h.rightMultiply(vec);

	    ind++;

	} while (!(s0.equals(s1) && vec.getHammingWeight() == t));

	vec = (GF2Vector) vec.multiply(p);

	data = vec.getEncoded();
	data = Conversions.signConversion(n, t, data);
	byte[] sig = new byte[data.length + 8];
	System.arraycopy(data, 0, sig, 0, data.length);
	System.arraycopy(pad, 0, sig, data.length, 8);
	return sig;
    }

    /**
     * Verify a signature.
     * 
     * @param signature
     *                the signature to be verified
     * @return true if the signature is correct, false otherwise.
     */
    public boolean verify(byte[] signature) {
	boolean verifyKey = false;

	if (signature.length < 9) {
	    return false;
	}

	int k = pubKey.getK();
	int n = pubKey.getN();
	int t = pubKey.getT();
	GF2Matrix matrixH = pubKey.getH();

	byte[] data = getData();
	data = md.digest(data);

	int z = signature.length - 8;
	byte[] help = new byte[data.length + 8];
	System.arraycopy(data, 0, help, 0, data.length);
	System.arraycopy(signature, z, help, data.length, 8);

	help = md.digest(help);

	int q = k >>> 3;
	int r = Math.min(q, md.getDigestLength());
	if ((k & 7) != 0) {
	    q++;
	}

	data = new byte[q];
	System.arraycopy(help, 0, data, 0, r);

	GF2Vector vecT = GF2Vector.OS2VP(k, data);

	byte[] s0 = new byte[z];
	System.arraycopy(signature, 0, s0, 0, z);

	GF2Vector vec = Conversions.encode(n, t, s0);
	vec = (GF2Vector) matrixH.rightMultiplyRightCompactForm(vec);
	verifyKey = vec.equals(vecT);
	return verifyKey;
    }

    /**
     * Convert the ByteArrayOutputStream into a byte array and close the stream.
     * 
     * @return the contents of the stream
     */
    private byte[] getData() {
	byte[] data = baos.toByteArray();

	try {
	    baos.close();
	} catch (IOException ioe) {
	    System.out.println("Can not close ByteArrayOutputStream");
	}
	baos.reset();
	return data;
    }

}
