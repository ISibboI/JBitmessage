package de.flexiprovider.pqc.rainbow;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.pqc.rainbow.util.ComputeInField;
import de.flexiprovider.pqc.rainbow.util.GF2Field;

/**
 * This class extends the KeyPairGenerator in the FlexiProvider_API. It is used
 * as a generator for the private and public key of the Rainbow Signature
 * Scheme.
 * 
 * Detailed information about the key generation is to be found in the paper of
 * Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable Polynomial
 * Signature Scheme. ACNS 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 * 
 * @author Patrick Neugebauer
 * @author Marius Senftleben
 * @author Tsvetoslava Vateva
 * 
 */
public class RainbowKeyPairGenerator extends KeyPairGenerator {

	private boolean initialized = false;
	private SecureRandom sr;
	private RainbowParameterSpec rainbowParams;

	// the OID string of the algorithm
    private String oid = "1.3.6.1.4.1.8301.3.1.3.5.3.2";
    
	/* linear affine map L1: */
	private short[][] A1; // matrix of the lin. affine map L1(n-v1 x n-v1 matrix)
	private short[][] A1inv; // inverted A1
	private short[] b1; // translation element of the lin.affine map L1

	/* linear affine map L2: */
	private short[][] A2; // matrix of the lin. affine map (n x n matrix)
	private short[][] A2inv; // inverted A2
	private short[] b2; // translation elemt of the lin.affine map L2

	/* components of F: */
	private int numOfLayers; // u (number of sets S)
	private Layer layers[]; // layers of polynomials of F
	private int[] vi; // set of vinegar vars per layer.

	/* components of Public Key */
	private short[][] pub_quadratic; // quadratic(mixed) coefficients
	private short[][] pub_singular; // singular coefficients
	private short[] pub_scalar; // scalars

	/**
	 * This function generates a Rainbow key pair, consisting of a
	 * {@link RainbowPublicKey} and a {@link RainbowPrivateKey}.
	 * 
	 * @return the generated key pair
	 */
	public KeyPair genKeyPair() {
		RainbowPrivateKey privKey;
		RainbowPublicKey pubKey;

		if (!initialized) {
			initializeDefault();
		}

		/* choose all coefficients at random */
		keygen();
		
		/* now marshall them to PrivateKey */
		privKey = new RainbowPrivateKey(oid, A1inv, b1, A2inv, b2, vi, layers);


		/* marshall to PublicKey */
		pubKey = new RainbowPublicKey(oid, vi[vi.length - 1] - vi[0],pub_quadratic,pub_singular,pub_scalar);

		return new KeyPair(pubKey, privKey);
	}

	/**
	 * This function is used for initialization of the {@link RainbowKeyPairGenerator} 
	 * making use of {@link RanbowParameterSpec}. 
	 * @param params
	 * @param random
	 * 			source of randomness
	 */
	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		/* params */

		if (params == null) {
			this.rainbowParams = new RainbowParameterSpec();
		} else if (params instanceof RainbowParameterSpec) {
			this.rainbowParams = (RainbowParameterSpec) params;
		} else {
			throw new InvalidAlgorithmParameterException("unsupported type");
		}

		/* set source of randomness */
		this.sr = (random == null) ? Registry.getSecureRandom() : random;

		/* unmarshalling: */
		this.vi = this.rainbowParams.getVi();
		this.numOfLayers = this.rainbowParams.getNumOfLayers();

		this.initialized = true;
	}

	/**
	 * This function initializes the key pair generator with the given key size.
	 * 
	 * @param keySize
	 *				
	 * @param random
	 *            the source of randomness
	 */
	public void initialize(int keysize, SecureRandom random)
			throws InvalidParameterException {
		RainbowParameterSpec rbParams = new RainbowParameterSpec();
		try {
			initialize(rbParams, random);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(
					"Internal error. The parameters are correct and must be accepted.");
		}
	}

	private void initializeDefault() {
		RainbowParameterSpec rbParams = new RainbowParameterSpec();
		try {
			initialize(rbParams, Registry.getSecureRandom());
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(
					"internal error. the parameters are correct and must be accepted. basta.");
		}

	}

	/**
	 * This function calls the functions for the random generation of the coefficients
	 * and the matrices needed for the private key and the method for computing the public key.
	 */
	private void keygen() {
		generateL1();
		generateL2();
		generateF();
		computePublicKey();
	}

	/**
	 * This function generates the invertible affine linear map L1 = A1*x + b1
	 * 
	 * The translation part b1, is stored in a separate array. The inverse of
	 * the matrix-part of L1 A1inv is also computed here.
	 * 
	 * This linear map hides the output of the map F. It is on k^(n-v1).
	 */
	private void generateL1() {

		// dimension = n-v1 = vi[last] - vi[first]
		int dim = vi[vi.length - 1] - vi[0];
		this.A1 = new short[dim][dim];
		this.A1inv = null;
		ComputeInField c = new ComputeInField();

		/* generation of A1 at random */
		while (A1inv == null) {
			for (int i = 0; i < dim; i++) {
				for (int j = 0; j < dim; j++) {
					A1[i][j] =(short) (sr.nextInt() & GF2Field.MASK);
				}
			}
			A1inv = c.inverse(A1);
		}

		/* generation of the translation vector at random */
		b1 = new short[dim];
		for (int i = 0; i < dim; i++) {
			b1[i] = (short) (sr.nextInt() & GF2Field.MASK);
		}
	}

	/**
	 * This function generates the invertible affine linear map L2 = A2*x + b2
	 * 
	 * The translation part b2, is stored in a separate array. The inverse of
	 * the matrix-part of L2 A2inv is also computed here.
	 * 
	 * This linear map hides the output of the map F. It is on k^(n).
	 */
	private void generateL2() {
		
		// dimension = n = vi[last]
		int dim = vi[vi.length - 1];
		this.A2 = new short[dim][dim];
		this.A2inv = null;
		ComputeInField c = new ComputeInField();

		/* generation of A2 at random */
		while (this.A2inv == null) {
			for (int i = 0; i < dim; i++) {
				for (int j = 0; j < dim; j++) { // one col extra for b
					A2[i][j] = (short) (sr.nextInt() & GF2Field.MASK);
				}
			}
			this.A2inv = c.inverse(A2);
		}
		/* generation of the translation vector at random */
		b2 = new short[dim];
		for (int i = 0; i < dim; i++) {
			b2[i] = (short) (sr.nextInt() & GF2Field.MASK);
		}

	}

	/**
	 * This function generates the private map F, which consists of u-1 layers.
	 * Each layer consists of oi polynomials where oi = vi[i+1]-vi[i].
	 * 
	 * The methods for the generation of the coefficients of these polynomials
	 * are called here.
	 */
	private void generateF() {

		this.layers = new Layer[this.numOfLayers];
		for (int i = 0; i < this.numOfLayers; i++) {
			layers[i] = new Layer(i, this.vi[i], this.vi[i + 1]);
			layers[i].generateCoefficients(this.sr);
		}
	}

	/**
	 * This function computes the public key from the private key.
	 * 
	 * The composition of F with L2 is computed, followed by applying L1 to the
	 * composition's result. The singular and scalar values constitute to the
	 * public key as is, the quadratic terms are compacted in
	 * <tt>compactPublicKey()</tt>
	 */
	public void computePublicKey() {
		
		ComputeInField c = new ComputeInField();
		int rows = this.vi[this.vi.length - 1] - this.vi[0];
		int vars = this.vi[this.vi.length - 1];
		// Fpub
		short[][][] coeff_quadratic_3dim = new short[rows][vars][vars];
		this.pub_singular = new short[rows][vars];
		this.pub_scalar = new short[rows];

		// Coefficients of layers of Private Key F
		short[][][] coeff_alpha;
		short[][][] coeff_beta;
		short[][] coeff_gamma;
		short[] coeff_eta;

		// Needed for counters;
		int oils = 0;
		int vins = 0;
		int crnt_row = 0; // current row (polynomial)

		short vect_tmp[] = new short[vars]; // vector tmp;
		short sclr_tmp = 0;

		// Composition of F and L2: Insert L2 = A2*x+b2 in F
		for (int l = 0; l < this.layers.length; l++) {
			// get coefficients of current layer
			coeff_alpha = this.layers[l].getCoeffAlpha();
			coeff_beta = this.layers[l].getCoeffBeta();
			coeff_gamma = this.layers[l].getCoeffGamma();
			coeff_eta = this.layers[l].getCoeffEta();
			oils = coeff_alpha[0].length;// this.layers[l].getOi();
			vins = coeff_beta[0].length;// this.layers[l].getVi();
			// compute polynomials of layer
			for (int p = 0; p < oils; p++) {
				// multiply alphas
				for (int x1 = 0; x1 < oils; x1++) {
					for (int x2 = 0; x2 < vins; x2++) {
						// multiply polynomial1 with polynomial2
						vect_tmp = c.multVect(coeff_alpha[p][x1][x2],
								this.A2[x1 + vins]);
						coeff_quadratic_3dim[crnt_row + p] = c.addSquareMatrix(
								coeff_quadratic_3dim[crnt_row + p], c
										.multVects(vect_tmp, this.A2[x2]));
						// mul poly1 with scalar2
						vect_tmp = c.multVect(this.b2[x2], vect_tmp);
						this.pub_singular[crnt_row + p] = c.addVect(vect_tmp,
								this.pub_singular[crnt_row + p]);
						// mul scalar1 with poly2
						vect_tmp = c.multVect(coeff_alpha[p][x1][x2],
								this.A2[x2]);
						vect_tmp = c.multVect(b2[x1 + vins], vect_tmp);
						this.pub_singular[crnt_row + p] = c.addVect(vect_tmp,
								this.pub_singular[crnt_row + p]);
						// mul scalar1 with scalar2
						sclr_tmp = GF2Field.multElem(coeff_alpha[p][x1][x2],
								this.b2[x1 + vins]);
						this.pub_scalar[crnt_row + p] = GF2Field.addElem(
								this.pub_scalar[crnt_row + p], GF2Field
										.multElem(sclr_tmp, this.b2[x2]));
					}
				}
				// multiply betas
				for (int x1 = 0; x1 < vins; x1++) {
					for (int x2 = 0; x2 < vins; x2++) {
						// multiply polynomial1 with polynomial2
						vect_tmp = c.multVect(coeff_beta[p][x1][x2],
								this.A2[x1]);
						coeff_quadratic_3dim[crnt_row + p] = c.addSquareMatrix(
								coeff_quadratic_3dim[crnt_row + p], c
										.multVects(vect_tmp, this.A2[x2]));
						// mul poly1 with scalar2
						vect_tmp = c.multVect(this.b2[x2], vect_tmp);
						this.pub_singular[crnt_row + p] = c.addVect(vect_tmp,
								this.pub_singular[crnt_row + p]);
						// mul scalar1 with poly2
						vect_tmp = c.multVect(coeff_beta[p][x1][x2],
								this.A2[x2]);
						vect_tmp = c.multVect(this.b2[x1], vect_tmp);
						this.pub_singular[crnt_row + p] = c.addVect(vect_tmp,
								this.pub_singular[crnt_row + p]);
						// mul scalar1 with scalar2
						sclr_tmp = GF2Field.multElem(coeff_beta[p][x1][x2],
								this.b2[x1]);
						this.pub_scalar[crnt_row + p] = GF2Field.addElem(
								this.pub_scalar[crnt_row + p], GF2Field
										.multElem(sclr_tmp, this.b2[x2]));
					}
				}
				// multiply gammas
				for (int n = 0; n < vins + oils; n++) {
					// mul poly with scalar
					vect_tmp = c.multVect(coeff_gamma[p][n], this.A2[n]);
					this.pub_singular[crnt_row + p] = c.addVect(vect_tmp,
							this.pub_singular[crnt_row + p]);
					// mul scalar with scalar
					this.pub_scalar[crnt_row + p] = GF2Field.addElem(
							this.pub_scalar[crnt_row + p], GF2Field.multElem(
									coeff_gamma[p][n], this.b2[n]));
				}
				// add eta
				this.pub_scalar[crnt_row + p] = GF2Field.addElem(
						this.pub_scalar[crnt_row + p], coeff_eta[p]);
			}
			crnt_row = crnt_row + oils;
		}

		// Apply L1 = A1*x+b1 to composition of F and L2
		{
			// temporary coefficient arrays
			short[][][] tmp_c_quad = new short[rows][vars][vars];
			short[][] tmp_c_sing = new short[rows][vars];
			short[] tmp_c_scal = new short[rows];
			for (int r = 0; r < rows; r++) {
				for (int q = 0; q < A1.length; q++) {
					tmp_c_quad[r] = c.addSquareMatrix(tmp_c_quad[r], c
							.multMatrix(A1[r][q], coeff_quadratic_3dim[q]));
					tmp_c_sing[r] = c.addVect(tmp_c_sing[r], c.multVect(
							A1[r][q], this.pub_singular[q]));
					tmp_c_scal[r] = GF2Field.addElem(tmp_c_scal[r], GF2Field
							.multElem(A1[r][q], this.pub_scalar[q]));
				}
				tmp_c_scal[r] = GF2Field.addElem(tmp_c_scal[r], b1[r]);
			}
			// set public key
			coeff_quadratic_3dim = tmp_c_quad;
			this.pub_singular = tmp_c_sing;
			this.pub_scalar = tmp_c_scal;
		}
		compactPublicKey(coeff_quadratic_3dim);
	}

	/**
	 * The quadratic (or mixed) terms of the public key are compacted from a n x
	 * n matrix per polynomial to an upper diagonal matrix stored in one integer
	 * array of n (n + 1) / 2 elements per polynomial. The ordering of elements
	 * is lexicographic and the result is updating <tt>this.pub_quadratic</tt>,
	 * which stores the quadratic elements of the public key.
	 * 
	 * @param coeff_quadratic_to_compact
	 *            3-dimensional array containing a n x n Matrix for each of the
	 *            n - v1 polynomials
	 */
	public void compactPublicKey(short[][][] coeff_quadratic_to_compact) {
		int polynomials = coeff_quadratic_to_compact.length;
		int n = coeff_quadratic_to_compact[0].length;
		int entries = n * (n + 1) / 2;// the small gauss
		this.pub_quadratic = new short[polynomials][entries];
		int offset = 0;

		for (int p = 0; p < polynomials; p++) {
			offset = 0;
			for (int x = 0; x < n; x++) {
				for (int y = x; y < n; y++) {
					if (y == x)
						this.pub_quadratic[p][offset] = coeff_quadratic_to_compact[p][x][y];
					else
						this.pub_quadratic[p][offset] = GF2Field.addElem(
								coeff_quadratic_to_compact[p][x][y],
								coeff_quadratic_to_compact[p][y][x]);
					offset++;
				}
			}
		}
	}

}
