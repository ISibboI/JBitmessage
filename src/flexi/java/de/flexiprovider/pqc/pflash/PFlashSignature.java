package de.flexiprovider.pqc.pflash;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.finitefields.GF2Polynomial;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialElement;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialField;
import de.flexiprovider.common.math.linearalgebra.GF2mMatrix;
import de.flexiprovider.common.math.linearalgebra.GF2mVector;

/**
 * <p>
 * This class implements the pFLASH signature scheme.
 * It only works when the parameters are set to <br/>
 * q = 16, n = 96, &#945 = r = 32, s = 1.
 * </p>
 * <p>
 * With these values the length of the hash of the message, that should be signed,
 * must be 256 bits. For that reason we chose SHA-256 as the message digest.
 * </p>
 * <p>
 * The PFlashSignature can be used as follow:
 * </p>
 * <p><b> Signature generation</b></p>
 * <ol>
 * <li> get instance of PFlashSignature
 * <tt> Signature pflashSig = Registry.getSignature("pFLASH");</tt></li>
 * <li> initialize signing<br/>
 * <tt> pflashSig.initSign(privateKey, secureRandom);</tt></li>
 * <li> sign message<br/>
 * <tt> pflashSig.update(message.getBytes());<br/>
 * byte[] signature = pflashSign.sign();</tt></li>
 * </ol>
 * <p><b> Signature verification</b></p>
 * <ol>
 * <li> initialize verifying<br/>
 * <tt> pflashSign.initVerify(publicKey);</tt></li>
 * <li> verify the signature<br/>
 * <tt> pflashSign.update(message.getBytes());<br/>
 * boolean accepted = pflashSign.verify(signature);</tt></li>
 * </ol>
 *
 * @author Marian Hornschuch, Alexander Koller
 * @see PFlashKeyPairGenerator
 */
public class PFlashSignature extends Signature {
    
    /**
     * OID of the algorithm
     */
    public static final String OID = "pFLASH";
    
    // private key
    private PFlashPrivateKey privateKey;
    
    // public key
    private PFlashPublicKey publicKey;
    
    /**
     * hashfunction used before signing -  Implementation with SHA256  
     */
    private MessageDigest md;
    
    // source of randomness
    private SecureRandom srandom;
    
    // q = 2<sup>m</sup>, alpha, r, s, n
    private int q, alpha, r, s, n;
    
    // GF(q = 2<sup>m</sup>)
    private GF2mField field_2m;
    
    // GF(2<sup>m*n</sup>)
    private GF2nPolynomialField field_2mn;
    
    // linear part of S,T - must be invertible
    private GF2mMatrix m_S,m_T;

    // affine part of S,T
    private GF2mVector c_S,c_T;
    
    private GF2Polynomial poly_384;
    
    /**
     * pFLASH Signature with SHA256<br/>
     * <p>
     * <b>The default values for the parameters are :</b><br/></p>
     * <table border="1">
     * <tr><td>degree of extension m</td><td>=</td><td>4</td></tr>
     * <tr><td>field polynomial of GF(2<sup>m</sup>)</td><td>=</td><td>X<sup>4</sup> + X + 1</td></tr>
     * <tr><td>extension degree of E/K</td><td>=</td><td>96</td></tr>
     * <tr><td>&#945</td><td>=</td><td>32</td></tr>
     * <tr><td>r</td><td>=</td><td>32</td></tr>
     * <tr><td>s</td><td>=</td><td>1</td></tr>
     * </table> 
     */
    public PFlashSignature() {
	q = 16;
	field_2m = new GF2mField(4, 19);
	n = 96;
	alpha = 32;
	r = 32;
	s = 1;
	try {
	    md = Registry.getMessageDigest("SHA256");
	} catch (NoSuchAlgorithmException e) {
	    e.printStackTrace();
	}
    }
    
    /**
     * Initialize the signature algorithm for signing a message.
     * 
     * @param key
     * 			the private key of the signer
     * @param srandom
     * 			a source of randomness
     * @throws InvalidKeyException
     * 			if the key is not an instance of PFlashPrivateKey
     */
    public void initSign(PrivateKey key, SecureRandom srandom)
    		throws InvalidKeyException {
	if (!(key instanceof PFlashPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	privateKey = (PFlashPrivateKey) key;
	
	// check if OID stored in the key matches algorithm OID
	if (!(privateKey.getOIDString().equals(OID))) {
	    throw new InvalidKeyException(
	    	"invalid key for this pFLASH instance");
	}
	
	this.srandom = (srandom != null) ? srandom : Registry.getSecureRandom();
	md.reset();
	
	m_S = privateKey.getM_S();
	c_S = privateKey.getC_S();
	m_T = privateKey.getM_T();
	c_T = privateKey.getC_T();
	poly_384 = privateKey.getPoly_384();
	field_2mn = new GF2nPolynomialField(384, poly_384);
    }
    
    /**
     * Initialize the signature algorithm for verifying a signature.
     * 
     * @param key
     * 			the public key of the signer
     * @throws InvalidKeyException
     * 			if the public key is not an instance of PFlashPublicKey
     */
    public void initVerify(PublicKey key)
    		throws InvalidKeyException {
	if (!(key instanceof PFlashPublicKey)) {
	    throw new InvalidKeyException("key is not a PFlashPublicKey");
	}
	publicKey = (PFlashPublicKey) key;
	
	// check if OID stored in the key matches algorithm OID
	if (!publicKey.getOIDString().equals(OID)) {
	    throw new InvalidKeyException(
		    "invalid key for this pFLASH instance");
	}
	
	
	// FIXME: set public key params and initialize other values
    }
    
    /**
     * Initialize this signature engine with specified parameter set (Not used)
     * 
     * @param params
     * 			the parameters (not used)
     */
    public void setParameters(AlgorithmParameterSpec params) {
	// parameters are not used
    }
    
    /**
     * Feed a message byte to the message digest.
     * @param input
     * 			the message byte
     */
    public void update(byte input) {
	md.update(input);
    }

    /**
     * Feed an array of message bytes to the message digest.
     * @param input
     * 			array of message bytes
     * @param inOff
     * 			index of message start
     * @param inLen
     * 			number of message bytes
     */
    public void update(byte[] input, int inOff, int inLen) {
	md.update(input, inOff, inLen);
    }

    /**
     * Sign a message.
     * 
     * @return the signature
     */
    public byte[] sign() {
	
	byte[] hash = md.digest();

	byte[] signature = new byte[n-s];
	boolean signFailed;
	// number of tries to sign (debug)
	byte rounds = 0;
	
	// repeat signing until last s elements of u are 0
	do {
	    signFailed = false;
	    rounds++;
	    
	    // #r GF(2^m)-elements chosen at random
	    byte[] k = new byte[r];
	    for (int i=0; i<r; i++) {
		k[i] = (byte) srandom.nextInt(0x10);
	    }
	    
	    // z = h || k_1 || ... || k_r
	    byte[] zbytes = new byte[n];
	    for (int i=0; i<hash.length; i++) {
		zbytes[2*i] = (byte) (hash[i]>>4 & 0x0f);
		zbytes[2*i+1] = (byte) (hash[i] & 0x0f);
	    }
	    System.arraycopy(k, 0, zbytes, 2*hash.length, k.length);
	    GF2mVector z = new GF2mVector(field_2m, zbytes);
	    
	    // y = S^(-1)(z)
	    GF2mVector y;
	    y = addVectors(z, c_S);
	    y = multiplyMatrixVector((GF2mMatrix) m_S.computeInverse(), y);

	    // x = Phi^(-1)(y) € E
	    byte[] yBytes = y.getEncoded();
	    byte[] xBytes = new byte[yBytes.length/2];
	    for (int i=0; i<xBytes.length; i++) {
		xBytes[i] = (byte) (yBytes[2*i]<<4 ^ yBytes[2*i+1]);
	    }
	    GF2Polynomial xPoly = new GF2Polynomial(8*xBytes.length, xBytes);
	    GF2nPolynomialElement x = new GF2nPolynomialElement(field_2mn, xPoly);
	
	    // compute mult. inverse h of 1+q^alpha mod (q^n-1)
	    FlexiBigInt modulus = new FlexiBigInt(String.valueOf(q));
	    modulus = modulus.pow(n);
	    modulus = modulus.subtract(FlexiBigInt.ONE);
	    FlexiBigInt exp = new FlexiBigInt(String.valueOf(q));
	    exp = exp.pow(alpha);
	    exp = exp.add(FlexiBigInt.ONE);
	    FlexiBigInt h = exp.modInverse(modulus);
	
	    // w = F^(-1)(x)
	    int lowestBit = h.getLowestSetBit();
	    int diff = lowestBit;

	    if (lowestBit != 0) {
		for (int i=0; i<diff; i++) {
		    x = x.squarePreCalc();
		}
	    }
	    GF2nPolynomialElement w = new GF2nPolynomialElement(x);
	    h.clearBit(lowestBit);
	    lowestBit = h.getLowestSetBit();
	    diff = lowestBit - diff;

	    // if all Bits are zero, lowestBit = -1
	    while (lowestBit != -1) {
		for (int i=0; i<diff; i++) {
		    x = x.squarePreCalc();
		}
		w.multiplyThisBy(x);
		h = h.clearBit(lowestBit);
		lowestBit = h.getLowestSetBit();
		diff = lowestBit - diff;
	    }
	   
	    // v = Phi(w) € K^n
	    byte[] vBytes = new byte[n];
	    byte[] wBytes = w.toByteArray();
	    for (int i=0; i<wBytes.length; i++) {
		vBytes[2*i] = (byte) (wBytes[i]>>>4 & 0x0f);
		vBytes[2*i+1] = (byte) (wBytes[i] & 0x0f);
	    }
	    GF2mVector v = new GF2mVector(field_2m, vBytes);
	
	    // u = T^(-1)(v)
	    GF2mVector u;
	    u = addVectors(v, c_T);
	    u = multiplyMatrixVector((GF2mMatrix) m_T.computeInverse(), u);
	
	    // sign = (u_1, ..., u_n-s)		, if last s elements == 0
	    // choose other random values in k	, else
	    byte[] uBytes = u.getEncoded();

	    for (int i=0; i<s; i++) {
		if (uBytes[uBytes.length-1-i] != 0) {
		    signFailed = true;
		}
	    }
	    System.arraycopy(uBytes, 0, signature, 0, n-s);
	    // debug
	    System.out.println("Rounds: "+rounds);
	} while (signFailed);
	// debug
	System.out.println("Signature accepted.");
	
	return signature;
    }
    
    /**
     * Verfify a signature.
     * 
     * @param signature
     * 			the signature to be verified
     * @return true if signature is valid, false otherwise
     */
    public boolean verify(byte[] sigBytes) {
    	
    	byte[] zstrichBytes=new byte[n-r];
    	boolean accepted = true;
    	GF2mVector q_vec;
    	GF2mVector p_vec;
    	GF2Polynomial p;
    	PFlashPublicKeyElement pfpke;
    	
    	for (int i = 0; i < sigBytes.length; i++){
    		pfpke = publicKey.getElement(i);
    		//hier müsste statt null die MultiplikationsMatrix für GF(1&) rein
    		q_vec = multiplyMatrixVector(pfpke.getQ_Matrix(), null);
    		p_vec = pfpke.getP_Vector();
    		p = new GF2Polynomial(96, p_vec.getIntArrayForm());
    		/*
    		 * GF2nPolynomialDarstellung q_vec + p + pfpke.getR();
    		 * Ergebnis einsetzen in zstrichBytes[i]
    		 */
    	}
    	
    	for(int i=0; i < sigBytes.length; i++){
        	if(zstrichBytes[i]!=sigBytes[i]){
        		accepted = false;
        	}
        	if(!accepted){
        		i = sigBytes.length;
        	}
    		
    	}
    	
	    return accepted;
    }

    /**
     * Add two n-dimensional GF2mVectors. (No checks)
     * 
     * @param v
     * 		first Vector
     * @param w
     * 		second Vector
     * @return sum
     */
    private GF2mVector addVectors(GF2mVector v, GF2mVector w) {
	int[] vInt, wInt;
	int[] sumInt = new int[n];
	vInt = v.getIntArrayForm();
	wInt = w.getIntArrayForm();
	for (int i=0; i<n; i++) {
	    sumInt[i] = field_2m.add(vInt[i], wInt[i]);
	}
	GF2mVector sum = new GF2mVector(field_2m, sumInt);
	return sum;
    }
    
    /**
     * Multiply n&timesn GF2mMatrix with n-dimensional GF2mVector. (No checks)
     * 
     * @param m
     * 		Matrix
     * @param v
     * 		Vector
     * @return Matrix*Vector
     */
    private GF2mVector multiplyMatrixVector(GF2mMatrix m, GF2mVector v) {
	byte[] mBytes;
	int[] vInt;
	int[] resultInt = new int[n];
	byte[] tmp = new byte[n];
	mBytes = m.getEncoded();
	vInt = v.getIntArrayForm();
	for (int i=0; i<n; i++) {
	    System.arraycopy(mBytes, n*i+4, tmp, 0, n);
	    for (int j=0; j<n; j++) {
		resultInt[i] = field_2m.add(resultInt[i], field_2m.mult(tmp[j], vInt[j]));
	    }
	}
	GF2mVector result = new GF2mVector(field_2m, resultInt);
	return result;
    }
}
