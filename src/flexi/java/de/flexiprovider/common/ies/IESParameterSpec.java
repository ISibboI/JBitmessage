/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.common.ies;

import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.desede.DESede;
import de.flexiprovider.core.desede.DESede.DESede_CBC;

/**
 * This class implements the {@link IES} algorithm parameters.
 * 
 * @author Marcus St&ouml;gbauer
 * @author Hristo Indzhov
 * @author Martin Döring
 * 
 * @see IES
 */
public class IESParameterSpec implements AlgorithmParameterSpec {

	/**
	 * The default symmetric cipher (AES128_CBC)
	 */
	public static final String DEFAULT_SYM_CIPHER = "AES128_CBC";

	/**
	 * The default MAC function (HmacSHA1)
	 */
	public static final String DEFAULT_MAC = "HmacSHA1";

	// the ephemeral key pair
	private KeyPair ephKeyPair;

	// the name of the desired symmetric cipher
	private String symCipherName;

	// the name of the key factory for the symmetric cipher
	private String mSymKFName;

	// the key size for the symmetric cipher
	private int mSymKeyLength;

	// the name of the desired MAC
	private String macName;

	// the name of the key factory for the MAC
	private String mMacKFName;

	// the encoding parameter used for the MAC
	private byte[] macEncParam;

	// the shared data used for the key derivation function
	private byte[] sharedInfo;

	// ****************************************************
	// JCA adapter methods
	// ****************************************************

	/**
	 * Constructor. If the specified symmetric cipher algorithm is <tt>null</tt>
	 * , the {@link #DEFAULT_SYM_CIPHER} is chosen. If the specified MAC
	 * function is <tt>null</tt>, the {@link #DEFAULT_MAC} is chosen.
	 * 
	 * @param ephKeyPair
	 *            the ephemeral key pair (used only for encryption)
	 * @param symCipherName
	 *            the name of the desired symmetric cipher algorithm ("internal"
	 *            for the internal cipher (one-time pad), or one of
	 *            "DESede_CBC", "AES128_CBC", "AES192_CBC", or "AES256_CBC").
	 * @param macName
	 *            the name of the desired MAC function ("HmacSHA1",
	 *            "HmacSHA256", "HmacSHA384", "HmacSHA512", or "HmacRIPEMD160").
	 * @param macEncParam
	 *            the encoding parameter used for the MAC
	 * @param sharedInfo
	 *            the shared data used for the key derivation function
	 * @throws java.security.InvalidParameterException
	 *             if the desired symmetric cipher algorithm or MAC function is
	 *             not supported.
	 */
	public IESParameterSpec(java.security.KeyPair ephKeyPair,
			String symCipherName, String macName, byte[] macEncParam,
			byte[] sharedInfo) throws java.security.InvalidParameterException {

		this(ephKeyPair == null ? null : new KeyPair((PublicKey) ephKeyPair
				.getPublic(), (PrivateKey) ephKeyPair.getPrivate()),
				symCipherName, macName, macEncParam, sharedInfo);
	}

	// ****************************************************
	// FlexiAPI methods
	// ****************************************************

	/**
	 * Constructor. Choose the {@link #DEFAULT_SYM_CIPHER} and the
	 * {@link #DEFAULT_MAC}. Set the encoding parameter for the MAC, the shared
	 * data for the key derivation function, and the ephemeral key pair to
	 * <tt>null</tt>.
	 */
	public IESParameterSpec() {
		this((KeyPair) null, DEFAULT_SYM_CIPHER, DEFAULT_MAC, null, null);
	}

	/**
	 * Constructor. If the specified symmetric cipher algorithm is <tt>null</tt>
	 * , the {@link #DEFAULT_SYM_CIPHER} is chosen. If the specified MAC
	 * function is <tt>null</tt>, the {@link #DEFAULT_MAC} is chosen.
	 * 
	 * @param symCipherName
	 *            the name of the desired symmetric cipher algorithm ("internal"
	 *            for the internal cipher (one-time pad), or one of
	 *            "DESede_CBC", "AES128_CBC", "AES192_CBC", or "AES256_CBC").
	 * @param macName
	 *            the name of the desired MAC function ("HmacSHA1",
	 *            "HmacSHA256", "HmacSHA384", "HmacSHA512", or "HmacRIPEMD160").
	 * @param macEncParam
	 *            the encoding parameter used for the MAC
	 * @param sharedInfo
	 *            the shared data used for the key derivation function
	 * @throws InvalidParameterException
	 *             if the desired symmetric cipher algorithm or MAC function is
	 *             not supported.
	 */
	public IESParameterSpec(String symCipherName, String macName,
			byte[] macEncParam, byte[] sharedInfo)
			throws InvalidParameterException {
		this((KeyPair) null, symCipherName, macName, macEncParam, sharedInfo);
	}

	/**
	 * Constructor. If the specified symmetric cipher algorithm is <tt>null</tt>
	 * , the {@link #DEFAULT_SYM_CIPHER} is chosen. If the specified MAC
	 * function is <tt>null</tt>, the {@link #DEFAULT_MAC} is chosen.
	 * 
	 * @param ephKeyPair
	 *            the ephemeral key pair (used only for encryption)
	 * @param symCipherName
	 *            the name of the desired symmetric cipher algorithm ("internal"
	 *            for the internal cipher (one-time pad), or one of
	 *            "DESede_CBC", "AES128_CBC", "AES192_CBC", or "AES256_CBC").
	 * @param macName
	 *            the name of the desired MAC function ("HmacSHA1",
	 *            "HmacSHA256", "HmacSHA384", "HmacSHA512", or "HmacRIPEMD160").
	 * @param macEncParam
	 *            the encoding parameter used for the MAC
	 * @param sharedInfo
	 *            the shared data used for the key derivation function
	 * @throws InvalidParameterException
	 *             if the desired symmetric cipher algorithm or MAC function is
	 *             not supported.
	 */
	public IESParameterSpec(KeyPair ephKeyPair, String symCipherName,
			String macName, byte[] macEncParam, byte[] sharedInfo)
			throws InvalidParameterException {

		this.ephKeyPair = ephKeyPair;
		setSymCipher(symCipherName);
		setMac(macName);
		this.macEncParam = ByteUtils.clone(macEncParam);
		this.sharedInfo = ByteUtils.clone(sharedInfo);
	}

	/*-------------------------------------------
	 * Getters
	 -------------------------------------------*/

	/**
	 * Return the ephemeral key pair. In case it is <tt>null</tt>, the IES
	 * implementation has to generate an ephemeral key pair itself.
	 * 
	 * @return the ephemeral key pair (may be <tt>null</tt>)
	 */
	public KeyPair getEphKeyPair() {
		return ephKeyPair;
	}

	/**
	 * @return the name of the symmetric cipher algorithm
	 */
	public String getSymCipherName() {
		return symCipherName;
	}

	/**
	 * @return the name of the key factory for the symmetric cipher algorithm
	 */
	protected String getSymKFName() {
		return mSymKFName;
	}

	/**
	 * @return the key length of the symmetric cipher algorithm
	 */
	protected int getSymKeyLength() {
		return mSymKeyLength;
	}

	/**
	 * @return the name of the MAC function
	 */
	public String getMacName() {
		return macName;
	}

	/**
	 * @return the name of the key factory for the MAC function
	 */
	protected String getMacKFName() {
		return mMacKFName;
	}

	/**
	 * @return the encoding parameters for the MAC function
	 */
	public byte[] getMacEncParam() {
		return ByteUtils.clone(macEncParam);
	}

	/**
	 * @return the shared data used for the key derivation function
	 */
	public byte[] getSharedInfo() {
		return ByteUtils.clone(sharedInfo);
	}

	private void setSymCipher(String symCipherName)
			throws InvalidParameterException {

		// if no symmetric algorithm is specified, choose the default one
		// (AES128_CBC)
		if (symCipherName == null || symCipherName.equals("")) {
			symCipherName = DEFAULT_SYM_CIPHER;
		}

		if (symCipherName.equals("internal")) {
			// internal cipher (one-time pad)
			this.symCipherName = null;
			mSymKFName = null;
			mSymKeyLength = 0;
		} else if (symCipherName.equals(DESede_CBC.ALG_NAME)) {
			this.symCipherName = symCipherName;
			mSymKFName = DESede.ALG_NAME;
			mSymKeyLength = 24;
		} else if (symCipherName.equals("AES128_CBC")) {
			this.symCipherName = symCipherName;
			mSymKFName = "AES";
			mSymKeyLength = 16;
		} else if (symCipherName.equals("AES192_CBC")) {
			this.symCipherName = symCipherName;
			mSymKFName = "AES";
			mSymKeyLength = 24;
		} else if (symCipherName.equals("AES256_CBC")) {
			this.symCipherName = symCipherName;
			mSymKFName = "AES";
			mSymKeyLength = 32;
		} else {
			throw new InvalidParameterException(
					"Unsupported symmetric cipher algorithm: '" + symCipherName
							+ "'.");
		}
	}

	private void setMac(String macName) throws InvalidParameterException {
		// if no MAC function is specified, use the default one (HmacSHA1)
		if (macName == null || macName.equals("")) {
			this.macName = DEFAULT_MAC;
			mMacKFName = "Hmac";
		} else if ((macName.equals("HmacSHA1"))
				|| (macName.equals("HmacSHA256"))
				|| (macName.equals("HmacSHA384"))
				|| (macName.equals("HmacSHA512"))
				|| (macName.equals("HmacRIPEMD160"))) {
			this.macName = macName;
			mMacKFName = "Hmac";
		} else {
			throw new InvalidParameterException("Unsupported MAC function: '"
					+ macName + "'.");
		}
	}

}
