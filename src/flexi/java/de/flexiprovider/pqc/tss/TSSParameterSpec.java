package de.flexiprovider.pqc.tss;

import java.util.Vector;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

public class TSSParameterSpec implements AlgorithmParameterSpec {

	// TODO: PS for public use!

	private TSSPrivateKey privKey = null;
	private TSSPublicKey pubKey = null;

	private TSSPolynomial gfp;

	private int m = 0;
	private int n = 0;
	private long p = 0;

	private TSSHashFunction hashFunction = null;

	public TSSParameterSpec(int n, long p) {

		this.n = n;
		m = (3 * TSS.floor2Log(n));
		this.p = p;
		hashFunction = new TSSHashFunction(generateA());

		Vector s = new Vector();
		s.setSize(m);
		long[] f = new long[n + 1];
		f[n] = 1;
		f[0] = 1;
		gfp = new TSSPolynomial(f, p, Registry.getSecureRandom());

		for (int i = 0; i < m; i++) {
			s.setElementAt(gfp.generatePoly(2, true), i);
		}

		privKey = new TSSPrivateKey(s);

		pubKey = new TSSPublicKey(hashFunction.calculatHash(privKey.getKey()));
	}

	public Vector generateA() {
		Vector result = new Vector();

		long[] f = new long[n + 1];
		f[n] = 1;
		f[0] = 1;
		TSSPolynomial generator = new TSSPolynomial(f, p, Registry
				.getSecureRandom());

		for (int i = 0; i < m; i++) {
			result.addElement(generator.generatePoly());
		}

		return result;
	}

	public TSSHashFunction getHFunction() {
		return hashFunction;
	}

	public int getM() {
		return m;
	}

	public int getN() {
		return n;
	}

	public long getP() {
		return p;
	}

	public TSSPrivateKey getPrivateKey() {
		return privKey;
	}

	public TSSPublicKey getPublicKey() {
		return pubKey;
	}

	public TSSPolynomial getRefGFP() {
		return gfp;
	}
}
