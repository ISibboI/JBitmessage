/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.desede;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.BigEndianConversions;

/**
 * This class implements the TripleDES (DESede) block cipher. The implementation
 * conforms to the <a
 * href="http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf">FIPS 46-3
 * standard</a>.
 * <p>
 * Note that the single DES algorithm can be emulated by TripleDES by
 * concatenating the same key three times.
 * 
 * @author Norbert Trummel
 * @author Sylvain Franke
 * @author Torsten Ehli
 * @author Oliver Seiler
 */
public class DESede extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "DESede";

	/**
	 * The DESede block size (8 bytes)
	 */
	public static final int blockSize = 8;

	// subkeys for the 3*16 rounds.
	private int[][] keys = new int[3][32];

	/**
	 * The following arrays contain the eight S-boxes combined with the
	 * permutation P. Compared to FIPS 46-3, the order of the elements has been
	 * changed to allow faster calculation of element positions. The new order
	 * of elements in each box is: 0-0, 1-0, 0-1, 1-1, ... , 0-15, 1-15 2-0,
	 * 3-0, 2-1, 3-1, ... , 2-15, 3-15
	 */

	private static int[] S1 = { 0x00808200, 0x00000000, 0x00008000, 0x00808202,
			0x00808002, 0x00008202, 0x00000002, 0x00008000, 0x00000200,
			0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002,
			0x00800000, 0x00000002, 0x00000202, 0x00800200, 0x00800200,
			0x00008200, 0x00008200, 0x00808000, 0x00808000, 0x00800202,
			0x00008002, 0x00800002, 0x00800002, 0x00008002, 0x00000000,
			0x00000202, 0x00008202, 0x00800000, 0x00008000, 0x00808202,
			0x00000002, 0x00808000, 0x00808200, 0x00800000, 0x00800000,
			0x00000200, 0x00808002, 0x00008000, 0x00008200, 0x00800002,
			0x00000200, 0x00000002, 0x00800202, 0x00008202, 0x00808202,
			0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202,
			0x00008202, 0x00808200, 0x00000202, 0x00800200, 0x00800200,
			0x00000000, 0x00008002, 0x00008200, 0x00000000, 0x00808002 };

	private static int[] S2 = { 0x40084010, 0x40004000, 0x00004000, 0x00084010,
			0x00080000, 0x00000010, 0x40080010, 0x40004010, 0x40000010,
			0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000,
			0x00000010, 0x40080010, 0x00084000, 0x00080010, 0x40004010,
			0x00000000, 0x40000000, 0x00004000, 0x00084010, 0x40080000,
			0x00080010, 0x40000010, 0x00000000, 0x00084000, 0x00004010,
			0x40084000, 0x40080000, 0x00004010, 0x00000000, 0x00084010,
			0x40080010, 0x00080000, 0x40004010, 0x40080000, 0x40084000,
			0x00004000, 0x40080000, 0x40004000, 0x00000010, 0x40084010,
			0x00084010, 0x00000010, 0x00004000, 0x40000000, 0x00004010,
			0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010,
			0x40000010, 0x00080010, 0x00084000, 0x00000000, 0x40004000,
			0x00004010, 0x40000000, 0x40080010, 0x40084010, 0x00084000 };

	private static int[] S3 = { 0x00000104, 0x04010100, 0x00000000, 0x04010004,
			0x04000100, 0x00000000, 0x00010104, 0x04000100, 0x00010004,
			0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004,
			0x04010000, 0x00000104, 0x04000000, 0x00000004, 0x04010100,
			0x00000100, 0x00010100, 0x04010000, 0x04010004, 0x00010104,
			0x04000104, 0x00010100, 0x00010000, 0x04000104, 0x00000004,
			0x04010104, 0x00000100, 0x04000000, 0x04010100, 0x04000000,
			0x00010004, 0x00000104, 0x00010000, 0x04010100, 0x04000100,
			0x00000000, 0x00000100, 0x00010004, 0x04010104, 0x04000100,
			0x04000004, 0x00000100, 0x00000000, 0x04010004, 0x04000104,
			0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104,
			0x00010100, 0x04000004, 0x04010000, 0x04000104, 0x00000104,
			0x04010000, 0x00010104, 0x00000004, 0x04010004, 0x00010100 };

	private static int[] S4 = { 0x80401000, 0x80001040, 0x80001040, 0x00000040,
			0x00401040, 0x80400040, 0x80400000, 0x80001000, 0x00000000,
			0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000,
			0x00400040, 0x80400000, 0x80000000, 0x00001000, 0x00400000,
			0x80401000, 0x00000040, 0x00400000, 0x80001000, 0x00001040,
			0x80400040, 0x80000000, 0x00001040, 0x00400040, 0x00001000,
			0x00401040, 0x80401040, 0x80000040, 0x00400040, 0x80400000,
			0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00000000,
			0x00401000, 0x00001040, 0x00400040, 0x80400040, 0x80000000,
			0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x80401040,
			0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000,
			0x00401040, 0x80400040, 0x80001000, 0x00001040, 0x00400000,
			0x80401000, 0x00000040, 0x00400000, 0x00001000, 0x00401040 };

	private static int[] S5 = { 0x00000080, 0x01040080, 0x01040000, 0x21000080,
			0x00040000, 0x00000080, 0x20000000, 0x01040000, 0x20040080,
			0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000,
			0x00040080, 0x20000000, 0x01000000, 0x20040000, 0x20040000,
			0x00000000, 0x20000080, 0x21040080, 0x21040080, 0x01000080,
			0x21040000, 0x20000080, 0x00000000, 0x21000000, 0x01040080,
			0x01000000, 0x21000000, 0x00040080, 0x00040000, 0x21000080,
			0x00000080, 0x01000000, 0x20000000, 0x01040000, 0x21000080,
			0x20040080, 0x01000080, 0x20000000, 0x21040000, 0x01040080,
			0x20040080, 0x00000080, 0x01000000, 0x21040000, 0x21040080,
			0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000,
			0x20040000, 0x21000000, 0x00040080, 0x01000080, 0x20000080,
			0x00040000, 0x00000000, 0x20040000, 0x01040080, 0x20000080 };

	private static int[] S6 = { 0x10000008, 0x10200000, 0x00002000, 0x10202008,
			0x10200000, 0x00000008, 0x10202008, 0x00200000, 0x10002000,
			0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000,
			0x10000000, 0x00002008, 0x00000000, 0x00200008, 0x10002008,
			0x00002000, 0x00202000, 0x10002008, 0x00000008, 0x10200008,
			0x10200008, 0x00000000, 0x00202008, 0x10202000, 0x00002008,
			0x00202000, 0x10202000, 0x10000000, 0x10002000, 0x00000008,
			0x10200008, 0x00202000, 0x10202008, 0x00200000, 0x00002008,
			0x10000008, 0x00200000, 0x10002000, 0x10000000, 0x00002008,
			0x10000008, 0x10202008, 0x00202000, 0x10200000, 0x00202008,
			0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000,
			0x10200000, 0x00202008, 0x00002000, 0x00200008, 0x10002008,
			0x00000000, 0x10202000, 0x10000000, 0x00200008, 0x10002008 };

	private static int[] S7 = { 0x00100000, 0x02100001, 0x02000401, 0x00000000,
			0x00000400, 0x02000401, 0x00100401, 0x02100400, 0x02100401,
			0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000,
			0x02100001, 0x00000401, 0x02000400, 0x00100401, 0x00100001,
			0x02000400, 0x02000001, 0x02100000, 0x02100400, 0x00100001,
			0x02100000, 0x00000400, 0x00000401, 0x02100401, 0x00100400,
			0x00000001, 0x02000000, 0x00100400, 0x02000000, 0x00100400,
			0x00100000, 0x02000401, 0x02000401, 0x02100001, 0x02100001,
			0x00000001, 0x00100001, 0x02000000, 0x02000400, 0x00100000,
			0x02100400, 0x00000401, 0x00100401, 0x02100400, 0x00000401,
			0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000,
			0x00000001, 0x02100401, 0x00000000, 0x00100401, 0x02100000,
			0x00000400, 0x02000001, 0x02000400, 0x00000400, 0x00100001 };

	private static int[] S8 = { 0x08000820, 0x00000800, 0x00020000, 0x08020820,
			0x08000000, 0x08000820, 0x00000020, 0x08000000, 0x00020020,
			0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820,
			0x00000800, 0x00000020, 0x08020000, 0x08000020, 0x08000800,
			0x00000820, 0x00020800, 0x00020020, 0x08020020, 0x08020800,
			0x00000820, 0x00000000, 0x00000000, 0x08020020, 0x08000020,
			0x08000800, 0x00020820, 0x00020000, 0x00020820, 0x00020000,
			0x08020800, 0x00000800, 0x00000020, 0x08020020, 0x00000800,
			0x00020820, 0x08000800, 0x00000020, 0x08000020, 0x08020000,
			0x08020020, 0x08000000, 0x00020000, 0x08000820, 0x00000000,
			0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800,
			0x08000820, 0x00000000, 0x08020820, 0x00020800, 0x00020800,
			0x00000820, 0x00000820, 0x00020020, 0x08000000, 0x08020800 };

	// =========================================================================================================

	/*
	 * Inner class providing DESede with predefined mode
	 */

	/**
	 * DESede_CBC
	 */
	public static class DESede_CBC extends DESede {

		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "DESede_CBC";

		/**
		 * The OID of DESede_CBC.
		 */
		public static final String OID = "1.2.840.113549.3.7";

		public DESede_CBC() {
			// set the mode
			try {
				setMode("CBC");
			} catch (NoSuchModeException e) {
				throw new RuntimeException(
						"Internal error: could not find CBC mode.");
			}
		}

		public String getName() {
			return ALG_NAME;
		}
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>DESedeKey</tt> or <tt>SecretKeySpec</tt>. If
	 * the 3 DES keys differ from each other, the effective key strength is 112
	 * bits (not 168 bits, due to a meet in the middle attack), if they are all
	 * equal, we're simulating single DES.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		boolean tripleDES = false;

		if (!((key instanceof DESedeKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a DESede Key");
		}

		byte[] keyBytes = key.getEncoded();

		// check if all three keys are equal. if so, we're
		// effectively dealing with single DES.
		for (int i = 0; i < 8; i++) {
			if (keyBytes[i] != keyBytes[i + 8]
					|| keyBytes[i + 8] != keyBytes[i + 16]) {
				tripleDES = true;
				break;
			}
		}

		// return effective key size
		return tripleDES ? 112 : 56;
	}

	/**
	 * Return the blocksize the algorithm uses. This method will usually be
	 * called by the padding scheme.
	 * 
	 * @return the used blocksize in Bytes.
	 */
	public int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * Initialize the cipher for encryption.
	 * 
	 * @param key
	 *            the secret key used for encryption
	 * @param params
	 *            algorithm parameters (not used)
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if (!(key instanceof DESedeKey)) {
			throw new InvalidKeyException("Not an instance of DESedeKey.");
		}
		keySchedule(key.getEncoded());
	}

	/**
	 * Initialize the cipher for decryption.
	 * 
	 * @param key
	 *            the secret key used for decryption
	 * @param params
	 *            algorithm parameters (not used)
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method implements the DESede Key schedule. The subkeys K_i are
	 * stored in the class variable <TT>keys</TT>. PC1: {0,1}^64 -> {0,1}^28 x
	 * {0,1}^28 PC2: {0,1}^28 x {0,1}^28 -> {0,1}^48 (C_0,D_0) = PC1(k) C_i =
	 * C_(i-1) << v_i D_i = D_(i-1) << v_i K_i = PC2(C_i,D_i)
	 * 
	 * @param key
	 *            the byte array containing the data for the key
	 */
	private void keySchedule(byte[] key) {
		int c, d; // Store C_i and D_i.
		int[] deskey = new int[2];

		for (int i = 0; i < 3; i++) {
			deskey[0] = ((key[i << 3] & 0xff) << 24)
					+ ((key[(i << 3) + 1] & 0xff) << 16)
					+ ((key[(i << 3) + 2] & 0xff) << 8)
					+ (key[(i << 3) + 3] & 0xff);
			deskey[1] = ((key[(i << 3) + 4] & 0xff) << 24)
					+ ((key[(i << 3) + 5] & 0xff) << 16)
					+ ((key[(i << 3) + 6] & 0xff) << 8)
					+ (key[(i << 3) + 7] & 0xff); // Convert
			// key
			// from
			// byte[]
			// to
			// two
			// integers.

			// ----- Start compute C_0 with upper half of PC1.
			c = (deskey[1] & 0x00000080) << 24; // 57-> 1
			c |= (deskey[1] & 0x00008000) << 15; // 49-> 2
			c |= (deskey[1] & 0x00800000) << 6; // 41-> 3
			c |= (deskey[1] & 0x80000000) >>> 3; // 33-> 4
			c |= (deskey[0] & 0x00000080) << 20; // 25-> 5
			c |= (deskey[0] & 0x00008000) << 11; // 17-> 6
			c |= (deskey[0] & 0x00800000) << 2; // 9-> 7
			c |= (deskey[0] & 0x80000000) >>> 7; // 1-> 8
			c |= (deskey[1] & 0x00000040) << 17; // 58-> 9
			c |= (deskey[1] & 0x00004000) << 8; // 50->10
			c |= (deskey[1] & 0x00400000) >>> 1; // 42->11
			c |= (deskey[1] & 0x40000000) >>> 10; // 34->12
			c |= (deskey[0] & 0x00000040) << 13; // 26->13
			c |= (deskey[0] & 0x00004000) << 4; // 18->14
			c |= (deskey[0] & 0x00400000) >>> 5; // 10->15
			c |= (deskey[0] & 0x40000000) >>> 14; // 2->16
			c |= (deskey[1] & 0x00000020) << 10; // 59->17
			c |= (deskey[1] & 0x00002000) << 1; // 51->18
			c |= (deskey[1] & 0x00200000) >>> 8; // 43->19
			c |= (deskey[1] & 0x20000000) >>> 17; // 35->20
			c |= (deskey[0] & 0x00000020) << 6; // 27->21
			c |= (deskey[0] & 0x00002000) >>> 3; // 19->22
			c |= (deskey[0] & 0x00200000) >>> 12; // 11->23
			c |= (deskey[0] & 0x20000000) >>> 21; // 3->24
			c |= (deskey[1] & 0x00000010) << 3; // 60->25
			c |= (deskey[1] & 0x00001000) >>> 6; // 52->26
			c |= (deskey[1] & 0x00100000) >>> 15; // 44->27
			c |= (deskey[1] & 0x10000000) >>> 24; // 36->28
			// ----- End compute C_0.

			// ----- Start compute D_0 with lower half of PC1.
			d = (deskey[1] & 0x00000002) << 30; // 63-> 1
			d |= (deskey[1] & 0x00000204) << 21; // 55-> 2,62-> 9
			d |= (deskey[1] & 0x00020408) << 12; // 47-> 3,54->10,61->17
			d |= (deskey[1] & 0x02040800) << 3; // 39-> 4,46->11,53->18
			d |= (deskey[0] & 0x00000002) << 26; // 31-> 5
			d |= (deskey[0] & 0x00000204) << 17; // 23-> 6,30->13
			d |= (deskey[0] & 0x00020408) << 8; // 15-> 7,22->14,29->21
			d |= (deskey[0] & 0x02040800) >>> 1; // 7-> 8,14->15,21->22
			d |= (deskey[1] & 0x04080000) >>> 6; // 38->12,45->19
			d |= (deskey[0] & 0x04080000) >>> 10; // 6->16,13->23
			d |= (deskey[1] & 0x08000000) >>> 15; // 37->20
			d |= (deskey[0] & 0x08000000) >>> 19; // 5->24
			d |= (deskey[0] & 0x00000010) << 3; // 28->25
			d |= (deskey[0] & 0x00001000) >>> 6; // 20->26
			d |= (deskey[0] & 0x00100000) >>> 15; // 12->27
			d |= (deskey[0] & 0x10000000) >>> 24; // 4->28
			// ----- End compute D_0.

			for (int j = 0, l = 0, r = 1; j < 16; j++, l = j << 1, r = l + 1) {
				// ----- Start v_i.
				switch (j) {
				case 0:
				case 1:
				case 8:
				case 15:
					c = ((c << 1) & 0xffffffe0) | ((c & 0x80000000) >>> 27);
					d = ((d << 1) & 0xffffffe0) | ((d & 0x80000000) >>> 27);
					break;

				default:
					c = ((c << 2) & 0xffffffc0) | ((c & 0xc0000000) >>> 26);
					d = ((d << 2) & 0xffffffc0) | ((d & 0xc0000000) >>> 26);
					break;
				}
				// ----- End v_i.

				// ----- Start function PC2.
				keys[i][l] = (c & 0x00040000) << 5; // c14-> 9
				keys[i][l] |= (c & 0x00008000) << 7; // c17->10
				keys[i][l] |= c & 0x00200000; // c11->11
				keys[i][l] |= (c & 0x00000110) << 12; // c24->12,c28->16
				keys[i][l] |= (c & 0xa4000000) >>> 12; // c 1->13,c 3->15,c
				// 6->18
				keys[i][l] |= (c & 0x08000000) >>> 9; // c 5->14
				keys[i][l] |= (c & 0x00020020) >>> 2; // c15->17,c27->29
				keys[i][l] |= (c & 0x00000a00) << 2; // c21->19,c23->21
				keys[i][l] |= (c & 0x00401000) >>> 10; // c10->20,c20->30
				keys[i][l] |= (c & 0x00002000) >>> 3; // c19->22
				keys[i][l] |= (c & 0x00110000) >>> 11; // c12->23,c16->27
				keys[i][l] |= (c & 0x10000000) >>> 20; // c 4->24
				keys[i][l] |= (c & 0x00000040) << 1; // c26->25
				keys[i][l] |= (c & 0x01080000) >>> 18; // c 8->26,c13->31
				keys[i][l] |= (c & 0x02000000) >>> 21; // c 7->28
				keys[i][l] |= (c & 0x40000000) >>> 30; // c 2->32

				keys[i][r] = (d & 0x00080010) << 4; // d13->41,d28->56
				keys[i][r] |= (d & 0x00000100) << 14; // d24->42
				keys[i][r] |= (d & 0x20000000) >>> 8; // d 3->43
				keys[i][r] |= (d & 0x00800000) >>> 3; // d 9->44
				keys[i][r] |= (d & 0x00002200) << 6; // d19->45,d23->49
				keys[i][r] |= (d & 0x00000020) << 13; // d27->46
				keys[i][r] |= (d & 0x40000000) >>> 13; // d 2->47
				keys[i][r] |= (d & 0x00100000) >>> 4; // d12->48
				keys[i][r] |= (d & 0x00008880) >>> 1; // d17->50,d21->54,d25->58
				keys[i][r] |= (d & 0x08040000) >>> 14; // d 5->51,d14->60
				keys[i][r] |= d & 0x00001000; // d20->52
				keys[i][r] |= (d & 0x00010000) >>> 5; // d16->53
				keys[i][r] |= (d & 0x00200000) >>> 12; // d11->55
				keys[i][r] |= (d & 0x04000000) >>> 19; // d 6->57
				keys[i][r] |= (d & 0x00004000) >>> 9; // d18->59
				keys[i][r] |= (d & 0x00000400) >>> 7; // d22->61
				keys[i][r] |= (d & 0x01000000) >>> 22; // d 8->62
				keys[i][r] |= (d & 0x80000000) >>> 30; // d 1->63
				keys[i][r] |= (d & 0x10000000) >>> 28; // d 4->64
				// ----- End function PC2.
			}
			// Now we?ve got 16 subkeys K_i = PC2(C_i,D_i) which look like
			// 0x00XXXXXX 0x00XXXXXX.
		}
		// With this we?ve got 3*16 subkeys.
	}

	/**
	 * This method encrypts a single block of data, and may only be called, when
	 * the block cipher is in encrytion mode. It has to be assured, too, that
	 * the array <TT>in</TT> contains a whole block starting at
	 * <TT>inOffset</TT> and that <TT>out</TT> is large enough to hold an
	 * encrypted block starting at <TT>outOffset</TT>. Key schedule is according
	 * to the FIPS46.3 standard.
	 * 
	 * @param input
	 *            array of bytes which contains the plaintext to be encrypted
	 * @param inOff
	 *            index in array in, where the plaintext block starts
	 * @param output
	 *            array of bytes which will contain the ciphertext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the ciphertext block will start
	 */
	protected void singleBlockEncrypt(byte[] input, int inOff, byte[] output,
			int outOff) {

		// convert plaintext block into long integer
		long block = BigEndianConversions.OS2LIP(input, inOff);

		block = initialPermutation(block);

		// ----- Start encrypt - decrypt - encrypt.
		block = encryptDES(0, block);
		block = decryptDES(1, block);
		block = encryptDES(2, block);
		// ----- End encrypt - decrypt - encrypt.

		block = finalPermutation(block);

		// convert ciphertext block into byte array
		BigEndianConversions.I2OSP(block, output, outOff);
	}

	/**
	 * This method decrypts a single block of data, and may only be called, when
	 * the block cipher is in decryption mode. It has to be assured, too, that
	 * the array <TT>in</TT> contains a whole block starting at
	 * <TT>inOffset</TT> and that <TT>out</TT> is large enough to hold a
	 * decrypted block starting at <TT>outOffset</TT>. Key schedule is according
	 * to the FIPS46.3 standard.
	 * 
	 * @param input
	 *            array of bytes which contains the ciphertext to be decrypted
	 * @param inOff
	 *            index in array in, where the ciphertext block starts
	 * @param output
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the plaintext block will start
	 */
	protected void singleBlockDecrypt(byte[] input, int inOff, byte[] output,
			int outOff) {

		// convert ciphertext block into long integer
		long block = BigEndianConversions.OS2LIP(input, inOff);

		block = initialPermutation(block);

		// ----- Start decrypt - encrypt - decrypt.
		block = decryptDES(2, block);
		block = encryptDES(1, block);
		block = decryptDES(0, block);
		// ----- End decrypt - encrypt - decrypt.

		block = finalPermutation(block);

		// convert plaintext block into byte array
		BigEndianConversions.I2OSP(block, output, outOff);
	}

	// ====================================================================================================================
	//
	// Here starts the single DES part where the real work is done.
	//
	// ====================================================================================================================

	/**
	 * @param key
	 *            the single SecretKey which has to be used to encrypt data
	 * @param in
	 *            long integer which contains the plaintext to be encrypted
	 */
	private long encryptDES(int key, long in) {
		int L, R, save, c, left, right;

		L = (int) (in >>> 32);
		R = (int) in;

		for (int i = 0; i < 16; i++) {
			save = L;
			L = R;

			// ----- Start expansion permutation E. R (32 Bit) -> E(R) (48 Bit).
			left = ((R & 0x00000001) << 23) | ((R & 0xf8000000) >>> 9)
					| ((R & 0x1f800000) >>> 11) | ((R & 0x01f80000) >>> 13)
					| ((R & 0x001f8000) >>> 15);
			right = ((R & 0x0001f800) << 7) | ((R & 0x00001f80) << 5)
					| ((R & 0x000001f8) << 3) | ((R & 0x0000001f) << 1)
					| ((R & 0x80000000) >>> 31);
			// ----- End expansion permutaion E.

			left ^= keys[key][i << 1]; // E(R) xor K = B_1B_2B_3B_4B_5B_6B_7B_8
			right ^= keys[key][(i << 1) + 1];

			// ----- Start the infamous S-boxes.
			c = S1[left >>> 18] | S2[(left >>> 12) & 0x3f]
					| S3[(left >>> 6) & 0x3f] | S4[left & 0x3f]
					| S5[right >>> 18] | S6[(right >>> 12) & 0x3f]
					| S7[(right >>> 6) & 0x3f] | S8[right & 0x3f];
			// ----- End the infamous S-boxes.

			R = save ^ c; // R_i = L_(i-1) xor f_(K_i,R_(i-1)).
		}
		return (((long) R) << 32) | (((long) L << 32) >>> 32); // (R_16,L_16) =
		// (L_15 xor
		// f_(K_16,R_15),R15).
	}

	/**
	 * @param key
	 *            the single SecretKey which has to be used to decrypt data
	 * @param in
	 *            long integer which contains the ciphertext to be decrypted
	 */
	private long decryptDES(int key, long in) {
		int L, R, save, c, left, right;

		L = (int) (in >>> 32);
		R = (int) in;

		for (int i = 15; i > -1; i--) {
			save = L;
			L = R;

			// ----- Start expansion permutation E. R (32 Bit) -> E(R) (48 Bit).
			left = ((R & 0x00000001) << 23) | ((R & 0xf8000000) >>> 9)
					| ((R & 0x1f800000) >>> 11) | ((R & 0x01f80000) >>> 13)
					| ((R & 0x001f8000) >>> 15);
			right = ((R & 0x0001f800) << 7) | ((R & 0x00001f80) << 5)
					| ((R & 0x000001f8) << 3) | ((R & 0x0000001f) << 1)
					| ((R & 0x80000000) >>> 31);
			// ----- End expansion permutaion E.

			left ^= keys[key][i << 1]; // E(R) xor K = B_1B_2B_3B_4B_5B_6B_7B_8
			right ^= keys[key][(i << 1) + 1];

			// ----- Start the infamous S-boxes.
			c = S1[left >>> 18] | S2[(left >>> 12) & 0x3f]
					| S3[(left >>> 6) & 0x3f] | S4[left & 0x3f]
					| S5[right >>> 18] | S6[(right >>> 12) & 0x3f]
					| S7[(right >>> 6) & 0x3f] | S8[right & 0x3f];
			// ----- End the infamous S-boxes.

			R = save ^ c; // R_i = L_(i-1) xor f_(K_i,R_(i-1)).
		}
		return (((long) R) << 32) | (((long) L << 32) >>> 32); // (R_0,L_0) =
		// (L_1 xor
		// f_(K_1,R_1),R1).
	}

	/**
	 * The initial permutation occurs before round 1. It transposes the input
	 * block as described in the matrix IP. According to Bruce Schneier, Applied
	 * Cryptography: "The initial permutation and the corresponding final
	 * permutation do not affect DES?s security. [...] Since this bit-wise
	 * permutation is difficult in software (although it is trivial in
	 * hardware), many software implementations of DES leave out both the
	 * initial and final permutations." This implementation does IP and FP
	 * according to FIPS46-3.
	 */
	private long initialPermutation(long in) {
		long result;

		// ----- Start initial permutation IP.
		result = (in & 0x0000000000000040L) << 57; // 58-> 1
		result |= (in & 0x0000000000004000L) << 48; // 50-> 2
		result |= (in & 0x0000000000400001L) << 39; // 42-> 3,64->25
		result |= (in & 0x0000000040000100L) << 30; // 34-> 4,56->26
		result |= (in & 0x0000004000010000L) << 21; // 26-> 5,48->27
		result |= (in & 0x0000400001000008L) << 12; // 18-> 6,40->28,61->49
		result |= (in & 0x0040000100000800L) << 3; // 10-> 7,32->29,53->50
		result |= (in & 0x0000000000000010L) << 51; // 60-> 9
		result |= (in & 0x0000000000001000L) << 42; // 52->10
		result |= (in & 0x0000000000100000L) << 33; // 44->11
		result |= (in & 0x0000000010000080L) << 24; // 36->12,57->33
		result |= (in & 0x0000001000008000L) << 15; // 28->13,49->34
		result |= (in & 0x0000100000800002L) << 6; // 20->14,41->35,63->57
		result |= (in & 0x0000000000000004L) << 45; // 62->17
		result |= (in & 0x0000000000000400L) << 36; // 54->18
		result |= (in & 0x0000000000040000L) << 27; // 46->19
		result |= (in & 0x0000000004000020L) << 18; // 38->20,59->41
		result |= (in & 0x0000000400002000L) << 9; // 30->21,51->42
		result |= in & 0x0000040000200000L; // 22->22,43->43
		result |= (in & 0x4000010000080000L) >>> 6; // 2-> 8,24->30,45->51
		result |= (in & 0x0010000080000200L) >>> 3; // 12->15,33->36,55->58
		result |= (in & 0x1000008000020000L) >>> 12; // 4->16,25->37,47->59
		result |= (in & 0x0004000020000000L) >>> 9; // 14->23,35->44
		result |= (in & 0x0400002000000000L) >>> 18; // 6->24,27->45
		result |= (in & 0x0001000008000000L) >>> 15; // 16->31,37->52
		result |= (in & 0x0100000800000000L) >>> 24; // 8->32,29->53
		result |= (in & 0x0000800002000000L) >>> 21; // 17->38,39->60
		result |= (in & 0x0080000200000000L) >>> 30; // 9->39,31->61
		result |= (in & 0x8000020000000000L) >>> 39; // 1->40,23->62
		result |= (in & 0x0000200000000000L) >>> 27; // 19->46
		result |= (in & 0x0020000000000000L) >>> 36; // 11->47
		result |= (in & 0x2000000000000000L) >>> 45; // 3->48
		result |= (in & 0x0000080000000000L) >>> 33; // 21->54
		result |= (in & 0x0008000000000000L) >>> 42; // 13->55
		result |= (in & 0x0800000000000000L) >>> 51; // 5->56
		result |= (in & 0x0002000000000000L) >>> 48; // 15->63
		result |= (in & 0x0200000000000000L) >>> 57; // 7->64
		// ----- End initial permutation IP.

		return result;
	}

	/**
	 * Inverse of the initial permutation IP.
	 */
	private long finalPermutation(long in) {
		long result;

		// ----- Start final permutation FP.
		result = (in & 0x0000000001000004L) << 39; // 40-> 1,62->23
		result |= (in & 0x0100000400002000L) << 6; // 8-> 2,30->24,51->45
		result |= (in & 0x0000000000010000L) << 45; // 48-> 3
		result |= (in & 0x0001000008000020L) << 12; // 16-> 4,37->25,59->47
		result |= (in & 0x0000000000000100L) << 51; // 56-> 5
		result |= (in & 0x0000010000080000L) << 18; // 24-> 6,45->27
		result |= (in & 0x0000000000000001L) << 57; // 64-> 7
		result |= (in & 0x0000000100000800L) << 24; // 32-> 8,53->29
		result |= (in & 0x0000000002000008L) << 30; // 39-> 9,61->31
		result |= (in & 0x0000000000020000L) << 36; // 47->11
		result |= (in & 0x0002000010000040L) << 3; // 15->12,36->33,58->55
		result |= (in & 0x0000000000000200L) << 42; // 55->13
		result |= (in & 0x0000020000100000L) << 9; // 23->14,44->35
		result |= (in & 0x0000000000000002L) << 48; // 63->15
		result |= (in & 0x0000000200001000L) << 15; // 31->16,52->37
		result |= (in & 0x0000000004000010L) << 21; // 38->17,60->39
		result |= (in & 0x0000000000040000L) << 27; // 46->19
		result |= (in & 0x0000000000000400L) << 33; // 54->21
		result |= in & 0x0000040000200000L; // 22->22,43->43
		result |= (in & 0x0200000800004000L) >>> 3; // 7->10,29->32,50->53
		result |= (in & 0x0400001000008000L) >>> 12; // 6->18,28->40,49->61
		result |= (in & 0x0004000020000080L) >>> 6; // 14->20,35->41,57->63
		result |= (in & 0x0800002000000000L) >>> 21; // 5->26,27->48
		result |= (in & 0x0008000040000000L) >>> 15; // 13->28,34->49
		result |= (in & 0x0000080000400000L) >>> 9; // 21->30,42->51
		result |= (in & 0x1000004000000000L) >>> 30; // 4->34,26->56
		result |= (in & 0x0010000080000000L) >>> 24; // 12->36,33->57
		result |= (in & 0x0000100000800000L) >>> 18; // 20->38,41->59
		result |= (in & 0x2000008000000000L) >>> 39; // 3->42,25->64
		result |= (in & 0x0020000000000000L) >>> 33; // 11->44
		result |= (in & 0x0000200000000000L) >>> 27; // 19->46
		result |= (in & 0x4000000000000000L) >>> 48; // 2->50
		result |= (in & 0x0040000000000000L) >>> 42; // 10->52
		result |= (in & 0x0000400000000000L) >>> 36; // 18->54
		result |= (in & 0x8000000000000000L) >>> 57; // 1->58
		result |= (in & 0x0080000000000000L) >>> 51; // 9->60
		result |= (in & 0x0000800000000000L) >>> 45; // 17->62
		// ----- End final permutation FP.

		return result;
	}

}
