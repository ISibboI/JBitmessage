package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.pqc.hbc.PRNG;
import de.flexiprovider.pqc.ots.lm.LMOTSKeyPairGenerator;
import de.flexiprovider.pqc.ots.lm.LMOTSParameterSpec;
import de.flexiprovider.pqc.ots.lm.LMOTSPrivateKey;
import de.flexiprovider.pqc.ots.lm.LMOTSPublicKey;
import de.flexiprovider.pqc.ots.lm.LMOTSSignature;

public class LMOTS implements OTS {

	private LMOTSPrivateKey privKey;
	private LMOTSPublicKey pubKey;

	private LMOTSSignature lmots;

	private LMOTSParameterSpec pS;

	private boolean alreadyGenerated = false;
	
	/**
	 * Constructor.
	 * 
	 */
	public LMOTS() {
	    //pS = new LMOTSParameterSpec(256);
	}

	public boolean canComputeVerificationKeyFromSignature() {
		return true;
	}

	public byte[] computeVerificationKey(byte[] bytes, byte[] sigBytes) {
		return pubKey.getEncoded();
	}

	public void generateKeyPair(byte[] seed) {
		LMOTSKeyPairGenerator kpg = new LMOTSKeyPairGenerator();

		if (pS == null) {
			try {
				throw new Exception("init has to be called first!");
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		try {
			kpg.initialize(pS, Registry.getSecureRandom());

			KeyPair keyPair = kpg.genKeyPair();

			pubKey = (LMOTSPublicKey) keyPair.getPublic();
			privKey = (LMOTSPrivateKey) keyPair.getPrivate();

			alreadyGenerated = true;
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void generateSignatureKey(byte[] seed) {
		if (!alreadyGenerated) {
			generateKeyPair(null);
		}
	}

	public void generateVerificationKey() {
		if (!alreadyGenerated) {
			generateKeyPair(null);
		}
	}

	public int getSignatureLength() {
		return lmots.getSignatureLength();
	}

	public byte[] getVerificationKey() {
		return pubKey.getEncoded();
	}

	public int getVerificationKeyLength() {
		return 0;
	}

	public void init(MessageDigest md, PRNG rng) {
	    int mdLength = md.getDigestLength() * 8 + 1;
	    pS = new LMOTSParameterSpec(mdLength);
	    lmots = new LMOTSSignature.GENERIC(md);
	    try {
		lmots.setParameters(pS);
	    }
	    catch (InvalidAlgorithmParameterException e) {
		e.printStackTrace();
	    }   
/*		if (md.getClass().equals(SHA1.class)) {
			try {
				pS = new LMOTSParameterSpec(256);
				lmots = new LMOTSSignature.SHA1();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(SHA224.class)) {
			try {
				pS = new LMOTSParameterSpec(256);
				lmots = new LMOTSSignature.SHA224();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(SHA256.class)) {
			try {
				pS = new LMOTSParameterSpec(260);
				lmots = new LMOTSSignature.SHA256();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(SHA384.class)) {
			try {
				pS = new LMOTSParameterSpec(390);
				lmots = new LMOTSSignature.SHA384();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(SHA512.class)) {
			try {
				pS = new LMOTSParameterSpec(520);
				lmots = new LMOTSSignature.SHA512();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(RIPEMD128.class)) {
			try {
				pS = new LMOTSParameterSpec(140);
				lmots = new LMOTSSignature.RIPEMD128();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(RIPEMD160.class)) {
			try {
				pS = new LMOTSParameterSpec(260);
				lmots = new LMOTSSignature.RIPEMD160();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(RIPEMD256.class)) {
			try {
				pS = new LMOTSParameterSpec(260);
				lmots = new LMOTSSignature.RIPEMD256();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		} else if (md.getClass().equals(RIPEMD320.class)) {
			try {
				pS = new LMOTSParameterSpec(512);
				lmots = new LMOTSSignature.RIPEMD320();
				lmots.setParameters(pS);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		}
*/
	}

	public byte[] sign(byte[] bytes) {
		try {
			lmots.initSign(privKey);
			return lmots.sign(bytes);
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}

	public boolean verify(byte[] message, byte[] signedMessage, byte[] verificationKey) {
		try {
			lmots.initVerify(new LMOTSPublicKey(verificationKey));
			lmots.setMessage(message);
			return lmots.verify(message, signedMessage);
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
}
