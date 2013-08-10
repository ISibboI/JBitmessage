/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.camellia;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.BigEndianConversions;

/**
 * Camellia is 128 bit symmetric block cipher with a Feistel structure, jointly
 * developed by the Nippon Telegraph and Telephone Corporation and the
 * Mitsubishi Electric Corporation. It supports 128, 192, and 256 bit keys.
 * Encryption and decryption of a block of data is achieved in 18 rounds. For
 * more information, see <a
 * href="http://info.isl.ntt.co.jp/camellia">http://info
 * .isl.ntt.co.jp/camellia</a>.
 * 
 * @author Ralf-Philipp Weinmann
 * @author Martin Döring
 */
public class Camellia extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "Camellia";

	/*
	 * Inner classes providing concrete implementations of Camellia with a
	 * variety of modes and key sizes.
	 */

	/**
	 * Camellia128_CBC
	 */
	public static class Camellia128_CBC extends Camellia {

		/**
		 * The OID of Camellia128_CBC (defined by RFC 3657).
		 */
		public static final String OID = "1.2.392.200011.61.1.1.1.2";

		public Camellia128_CBC() {
			super("CBC", 128);
		}
	}

	/**
	 * Camellia192_CBC
	 */
	public static class Camellia192_CBC extends Camellia {

		/**
		 * The OID of Camellia192_CBC (defined by RFC 3657).
		 */
		public static final String OID = "1.2.392.200011.61.1.1.1.3";

		public Camellia192_CBC() {
			super("CBC", 192);
		}
	}

	/**
	 * Camellia256_CBC
	 */
	public static class Camellia256_CBC extends Camellia {

		/**
		 * The OID of Camellia256_CBC (defined by RFC 3657).
		 */
		public static final String OID = "1.2.392.200011.61.1.1.1.4";

		public Camellia256_CBC() {
			super("CBC", 256);
		}
	}

	// Block size is 16 bytes.
	private static final int blockSize = 16;

	// key size is one of 128, 192, or 256 (chosen by the constructor)
	private int keySize;

	// flag indicating whether the key size may be changed during
	// initialization
	private boolean keySizeIsMutable;

	private static final int[] KIDX1 = { 0, 0, 4, 4, 0, 0, 4, 4, 4, 4, 0, 0, 4,
			0, 4, 4, 0, 0, 0, 0, 4, 4, 0, 0, 4, 4 };

	private static final int[] KIDX2 = { 0, 0, 12, 12, 8, 8, 4, 4, 8, 8, 12,
			12, 0, 0, 4, 4, 0, 0, 8, 8, 12, 12, 0, 0, 4, 4, 8, 8, 4, 4, 0, 0,
			12, 12 };

	private static final int[] KSFT1 = { 0, 64, 0, 64, 15, 79, 15, 79, 30, 94,
			45, 109, 45, 124, 60, 124, 77, 13, 94, 30, 94, 30, 111, 47, 111, 47 };

	private static final int[] KSFT2 = { 0, 64, 0, 64, 15, 79, 15, 79, 30, 94,
			30, 94, 45, 109, 45, 109, 60, 124, 60, 124, 60, 124, 77, 13, 77,
			13, 94, 30, 94, 30, 111, 47, 111, 47 };

	private static final byte[] SIGMA = { (byte) 0xa0, (byte) 0x9e,
			(byte) 0x66, (byte) 0x7f, (byte) 0x3b, (byte) 0xcc, (byte) 0x90,
			(byte) 0x8b, (byte) 0xb6, (byte) 0x7a, (byte) 0xe8, (byte) 0x58,
			(byte) 0x4c, (byte) 0xaa, (byte) 0x73, (byte) 0xb2, (byte) 0xc6,
			(byte) 0xef, (byte) 0x37, (byte) 0x2f, (byte) 0xe9, (byte) 0x4f,
			(byte) 0x82, (byte) 0xbe, (byte) 0x54, (byte) 0xff, (byte) 0x53,
			(byte) 0xa5, (byte) 0xf1, (byte) 0xd3, (byte) 0x6f, (byte) 0x1c,
			(byte) 0x10, (byte) 0xe5, (byte) 0x27, (byte) 0xfa, (byte) 0xde,
			(byte) 0x68, (byte) 0x2d, (byte) 0x1d, (byte) 0xb0, (byte) 0x56,
			(byte) 0x88, (byte) 0xc2, (byte) 0xb3, (byte) 0xe6, (byte) 0xc1,
			(byte) 0xfd };

	/**
	 * SBOX #1
	 */
	private static final byte[] S1 = { (byte) 0x70, (byte) 0x82, (byte) 0x2c,
			(byte) 0xec, (byte) 0xb3, (byte) 0x27, (byte) 0xc0, (byte) 0xe5,
			(byte) 0xe4, (byte) 0x85, (byte) 0x57, (byte) 0x35, (byte) 0xea,
			(byte) 0x0c, (byte) 0xae, (byte) 0x41, (byte) 0x23, (byte) 0xef,
			(byte) 0x6b, (byte) 0x93, (byte) 0x45, (byte) 0x19, (byte) 0xa5,
			(byte) 0x21, (byte) 0xed, (byte) 0x0e, (byte) 0x4f, (byte) 0x4e,
			(byte) 0x1d, (byte) 0x65, (byte) 0x92, (byte) 0xbd, (byte) 0x86,
			(byte) 0xb8, (byte) 0xaf, (byte) 0x8f, (byte) 0x7c, (byte) 0xeb,
			(byte) 0x1f, (byte) 0xce, (byte) 0x3e, (byte) 0x30, (byte) 0xdc,
			(byte) 0x5f, (byte) 0x5e, (byte) 0xc5, (byte) 0x0b, (byte) 0x1a,
			(byte) 0xa6, (byte) 0xe1, (byte) 0x39, (byte) 0xca, (byte) 0xd5,
			(byte) 0x47, (byte) 0x5d, (byte) 0x3d, (byte) 0xd9, (byte) 0x01,
			(byte) 0x5a, (byte) 0xd6, (byte) 0x51, (byte) 0x56, (byte) 0x6c,
			(byte) 0x4d, (byte) 0x8b, (byte) 0x0d, (byte) 0x9a, (byte) 0x66,
			(byte) 0xfb, (byte) 0xcc, (byte) 0xb0, (byte) 0x2d, (byte) 0x74,
			(byte) 0x12, (byte) 0x2b, (byte) 0x20, (byte) 0xf0, (byte) 0xb1,
			(byte) 0x84, (byte) 0x99, (byte) 0xdf, (byte) 0x4c, (byte) 0xcb,
			(byte) 0xc2, (byte) 0x34, (byte) 0x7e, (byte) 0x76, (byte) 0x05,
			(byte) 0x6d, (byte) 0xb7, (byte) 0xa9, (byte) 0x31, (byte) 0xd1,
			(byte) 0x17, (byte) 0x04, (byte) 0xd7, (byte) 0x14, (byte) 0x58,
			(byte) 0x3a, (byte) 0x61, (byte) 0xde, (byte) 0x1b, (byte) 0x11,
			(byte) 0x1c, (byte) 0x32, (byte) 0x0f, (byte) 0x9c, (byte) 0x16,
			(byte) 0x53, (byte) 0x18, (byte) 0xf2, (byte) 0x22, (byte) 0xfe,
			(byte) 0x44, (byte) 0xcf, (byte) 0xb2, (byte) 0xc3, (byte) 0xb5,
			(byte) 0x7a, (byte) 0x91, (byte) 0x24, (byte) 0x08, (byte) 0xe8,
			(byte) 0xa8, (byte) 0x60, (byte) 0xfc, (byte) 0x69, (byte) 0x50,
			(byte) 0xaa, (byte) 0xd0, (byte) 0xa0, (byte) 0x7d, (byte) 0xa1,
			(byte) 0x89, (byte) 0x62, (byte) 0x97, (byte) 0x54, (byte) 0x5b,
			(byte) 0x1e, (byte) 0x95, (byte) 0xe0, (byte) 0xff, (byte) 0x64,
			(byte) 0xd2, (byte) 0x10, (byte) 0xc4, (byte) 0x00, (byte) 0x48,
			(byte) 0xa3, (byte) 0xf7, (byte) 0x75, (byte) 0xdb, (byte) 0x8a,
			(byte) 0x03, (byte) 0xe6, (byte) 0xda, (byte) 0x09, (byte) 0x3f,
			(byte) 0xdd, (byte) 0x94, (byte) 0x87, (byte) 0x5c, (byte) 0x83,
			(byte) 0x02, (byte) 0xcd, (byte) 0x4a, (byte) 0x90, (byte) 0x33,
			(byte) 0x73, (byte) 0x67, (byte) 0xf6, (byte) 0xf3, (byte) 0x9d,
			(byte) 0x7f, (byte) 0xbf, (byte) 0xe2, (byte) 0x52, (byte) 0x9b,
			(byte) 0xd8, (byte) 0x26, (byte) 0xc8, (byte) 0x37, (byte) 0xc6,
			(byte) 0x3b, (byte) 0x81, (byte) 0x96, (byte) 0x6f, (byte) 0x4b,
			(byte) 0x13, (byte) 0xbe, (byte) 0x63, (byte) 0x2e, (byte) 0xe9,
			(byte) 0x79, (byte) 0xa7, (byte) 0x8c, (byte) 0x9f, (byte) 0x6e,
			(byte) 0xbc, (byte) 0x8e, (byte) 0x29, (byte) 0xf5, (byte) 0xf9,
			(byte) 0xb6, (byte) 0x2f, (byte) 0xfd, (byte) 0xb4, (byte) 0x59,
			(byte) 0x78, (byte) 0x98, (byte) 0x06, (byte) 0x6a, (byte) 0xe7,
			(byte) 0x46, (byte) 0x71, (byte) 0xba, (byte) 0xd4, (byte) 0x25,
			(byte) 0xab, (byte) 0x42, (byte) 0x88, (byte) 0xa2, (byte) 0x8d,
			(byte) 0xfa, (byte) 0x72, (byte) 0x07, (byte) 0xb9, (byte) 0x55,
			(byte) 0xf8, (byte) 0xee, (byte) 0xac, (byte) 0x0a, (byte) 0x36,
			(byte) 0x49, (byte) 0x2a, (byte) 0x68, (byte) 0x3c, (byte) 0x38,
			(byte) 0xf1, (byte) 0xa4, (byte) 0x40, (byte) 0x28, (byte) 0xd3,
			(byte) 0x7b, (byte) 0xbb, (byte) 0xc9, (byte) 0x43, (byte) 0xc1,
			(byte) 0x15, (byte) 0xe3, (byte) 0xad, (byte) 0xf4, (byte) 0x77,
			(byte) 0xc7, (byte) 0x80, (byte) 0x9e, };

	/**
	 * SBOX #2
	 */
	private static final byte[] S2 = { (byte) 0xe0, (byte) 0x05, (byte) 0x58,
			(byte) 0xd9, (byte) 0x67, (byte) 0x4e, (byte) 0x81, (byte) 0xcb,
			(byte) 0xc9, (byte) 0x0b, (byte) 0xae, (byte) 0x6a, (byte) 0xd5,
			(byte) 0x18, (byte) 0x5d, (byte) 0x82, (byte) 0x46, (byte) 0xdf,
			(byte) 0xd6, (byte) 0x27, (byte) 0x8a, (byte) 0x32, (byte) 0x4b,
			(byte) 0x42, (byte) 0xdb, (byte) 0x1c, (byte) 0x9e, (byte) 0x9c,
			(byte) 0x3a, (byte) 0xca, (byte) 0x25, (byte) 0x7b, (byte) 0x0d,
			(byte) 0x71, (byte) 0x5f, (byte) 0x1f, (byte) 0xf8, (byte) 0xd7,
			(byte) 0x3e, (byte) 0x9d, (byte) 0x7c, (byte) 0x60, (byte) 0xb9,
			(byte) 0xbe, (byte) 0xbc, (byte) 0x8b, (byte) 0x16, (byte) 0x34,
			(byte) 0x4d, (byte) 0xc3, (byte) 0x72, (byte) 0x95, (byte) 0xab,
			(byte) 0x8e, (byte) 0xba, (byte) 0x7a, (byte) 0xb3, (byte) 0x02,
			(byte) 0xb4, (byte) 0xad, (byte) 0xa2, (byte) 0xac, (byte) 0xd8,
			(byte) 0x9a, (byte) 0x17, (byte) 0x1a, (byte) 0x35, (byte) 0xcc,
			(byte) 0xf7, (byte) 0x99, (byte) 0x61, (byte) 0x5a, (byte) 0xe8,
			(byte) 0x24, (byte) 0x56, (byte) 0x40, (byte) 0xe1, (byte) 0x63,
			(byte) 0x09, (byte) 0x33, (byte) 0xbf, (byte) 0x98, (byte) 0x97,
			(byte) 0x85, (byte) 0x68, (byte) 0xfc, (byte) 0xec, (byte) 0x0a,
			(byte) 0xda, (byte) 0x6f, (byte) 0x53, (byte) 0x62, (byte) 0xa3,
			(byte) 0x2e, (byte) 0x08, (byte) 0xaf, (byte) 0x28, (byte) 0xb0,
			(byte) 0x74, (byte) 0xc2, (byte) 0xbd, (byte) 0x36, (byte) 0x22,
			(byte) 0x38, (byte) 0x64, (byte) 0x1e, (byte) 0x39, (byte) 0x2c,
			(byte) 0xa6, (byte) 0x30, (byte) 0xe5, (byte) 0x44, (byte) 0xfd,
			(byte) 0x88, (byte) 0x9f, (byte) 0x65, (byte) 0x87, (byte) 0x6b,
			(byte) 0xf4, (byte) 0x23, (byte) 0x48, (byte) 0x10, (byte) 0xd1,
			(byte) 0x51, (byte) 0xc0, (byte) 0xf9, (byte) 0xd2, (byte) 0xa0,
			(byte) 0x55, (byte) 0xa1, (byte) 0x41, (byte) 0xfa, (byte) 0x43,
			(byte) 0x13, (byte) 0xc4, (byte) 0x2f, (byte) 0xa8, (byte) 0xb6,
			(byte) 0x3c, (byte) 0x2b, (byte) 0xc1, (byte) 0xff, (byte) 0xc8,
			(byte) 0xa5, (byte) 0x20, (byte) 0x89, (byte) 0x00, (byte) 0x90,
			(byte) 0x47, (byte) 0xef, (byte) 0xea, (byte) 0xb7, (byte) 0x15,
			(byte) 0x06, (byte) 0xcd, (byte) 0xb5, (byte) 0x12, (byte) 0x7e,
			(byte) 0xbb, (byte) 0x29, (byte) 0x0f, (byte) 0xb8, (byte) 0x07,
			(byte) 0x04, (byte) 0x9b, (byte) 0x94, (byte) 0x21, (byte) 0x66,
			(byte) 0xe6, (byte) 0xce, (byte) 0xed, (byte) 0xe7, (byte) 0x3b,
			(byte) 0xfe, (byte) 0x7f, (byte) 0xc5, (byte) 0xa4, (byte) 0x37,
			(byte) 0xb1, (byte) 0x4c, (byte) 0x91, (byte) 0x6e, (byte) 0x8d,
			(byte) 0x76, (byte) 0x03, (byte) 0x2d, (byte) 0xde, (byte) 0x96,
			(byte) 0x26, (byte) 0x7d, (byte) 0xc6, (byte) 0x5c, (byte) 0xd3,
			(byte) 0xf2, (byte) 0x4f, (byte) 0x19, (byte) 0x3f, (byte) 0xdc,
			(byte) 0x79, (byte) 0x1d, (byte) 0x52, (byte) 0xeb, (byte) 0xf3,
			(byte) 0x6d, (byte) 0x5e, (byte) 0xfb, (byte) 0x69, (byte) 0xb2,
			(byte) 0xf0, (byte) 0x31, (byte) 0x0c, (byte) 0xd4, (byte) 0xcf,
			(byte) 0x8c, (byte) 0xe2, (byte) 0x75, (byte) 0xa9, (byte) 0x4a,
			(byte) 0x57, (byte) 0x84, (byte) 0x11, (byte) 0x45, (byte) 0x1b,
			(byte) 0xf5, (byte) 0xe4, (byte) 0x0e, (byte) 0x73, (byte) 0xaa,
			(byte) 0xf1, (byte) 0xdd, (byte) 0x59, (byte) 0x14, (byte) 0x6c,
			(byte) 0x92, (byte) 0x54, (byte) 0xd0, (byte) 0x78, (byte) 0x70,
			(byte) 0xe3, (byte) 0x49, (byte) 0x80, (byte) 0x50, (byte) 0xa7,
			(byte) 0xf6, (byte) 0x77, (byte) 0x93, (byte) 0x86, (byte) 0x83,
			(byte) 0x2a, (byte) 0xc7, (byte) 0x5b, (byte) 0xe9, (byte) 0xee,
			(byte) 0x8f, (byte) 0x01, (byte) 0x3d, };

	/**
	 * SBOX #3
	 */
	private static final byte[] S3 = { (byte) 0x38, (byte) 0x41, (byte) 0x16,
			(byte) 0x76, (byte) 0xd9, (byte) 0x93, (byte) 0x60, (byte) 0xf2,
			(byte) 0x72, (byte) 0xc2, (byte) 0xab, (byte) 0x9a, (byte) 0x75,
			(byte) 0x06, (byte) 0x57, (byte) 0xa0, (byte) 0x91, (byte) 0xf7,
			(byte) 0xb5, (byte) 0xc9, (byte) 0xa2, (byte) 0x8c, (byte) 0xd2,
			(byte) 0x90, (byte) 0xf6, (byte) 0x07, (byte) 0xa7, (byte) 0x27,
			(byte) 0x8e, (byte) 0xb2, (byte) 0x49, (byte) 0xde, (byte) 0x43,
			(byte) 0x5c, (byte) 0xd7, (byte) 0xc7, (byte) 0x3e, (byte) 0xf5,
			(byte) 0x8f, (byte) 0x67, (byte) 0x1f, (byte) 0x18, (byte) 0x6e,
			(byte) 0xaf, (byte) 0x2f, (byte) 0xe2, (byte) 0x85, (byte) 0x0d,
			(byte) 0x53, (byte) 0xf0, (byte) 0x9c, (byte) 0x65, (byte) 0xea,
			(byte) 0xa3, (byte) 0xae, (byte) 0x9e, (byte) 0xec, (byte) 0x80,
			(byte) 0x2d, (byte) 0x6b, (byte) 0xa8, (byte) 0x2b, (byte) 0x36,
			(byte) 0xa6, (byte) 0xc5, (byte) 0x86, (byte) 0x4d, (byte) 0x33,
			(byte) 0xfd, (byte) 0x66, (byte) 0x58, (byte) 0x96, (byte) 0x3a,
			(byte) 0x09, (byte) 0x95, (byte) 0x10, (byte) 0x78, (byte) 0xd8,
			(byte) 0x42, (byte) 0xcc, (byte) 0xef, (byte) 0x26, (byte) 0xe5,
			(byte) 0x61, (byte) 0x1a, (byte) 0x3f, (byte) 0x3b, (byte) 0x82,
			(byte) 0xb6, (byte) 0xdb, (byte) 0xd4, (byte) 0x98, (byte) 0xe8,
			(byte) 0x8b, (byte) 0x02, (byte) 0xeb, (byte) 0x0a, (byte) 0x2c,
			(byte) 0x1d, (byte) 0xb0, (byte) 0x6f, (byte) 0x8d, (byte) 0x88,
			(byte) 0x0e, (byte) 0x19, (byte) 0x87, (byte) 0x4e, (byte) 0x0b,
			(byte) 0xa9, (byte) 0x0c, (byte) 0x79, (byte) 0x11, (byte) 0x7f,
			(byte) 0x22, (byte) 0xe7, (byte) 0x59, (byte) 0xe1, (byte) 0xda,
			(byte) 0x3d, (byte) 0xc8, (byte) 0x12, (byte) 0x04, (byte) 0x74,
			(byte) 0x54, (byte) 0x30, (byte) 0x7e, (byte) 0xb4, (byte) 0x28,
			(byte) 0x55, (byte) 0x68, (byte) 0x50, (byte) 0xbe, (byte) 0xd0,
			(byte) 0xc4, (byte) 0x31, (byte) 0xcb, (byte) 0x2a, (byte) 0xad,
			(byte) 0x0f, (byte) 0xca, (byte) 0x70, (byte) 0xff, (byte) 0x32,
			(byte) 0x69, (byte) 0x08, (byte) 0x62, (byte) 0x00, (byte) 0x24,
			(byte) 0xd1, (byte) 0xfb, (byte) 0xba, (byte) 0xed, (byte) 0x45,
			(byte) 0x81, (byte) 0x73, (byte) 0x6d, (byte) 0x84, (byte) 0x9f,
			(byte) 0xee, (byte) 0x4a, (byte) 0xc3, (byte) 0x2e, (byte) 0xc1,
			(byte) 0x01, (byte) 0xe6, (byte) 0x25, (byte) 0x48, (byte) 0x99,
			(byte) 0xb9, (byte) 0xb3, (byte) 0x7b, (byte) 0xf9, (byte) 0xce,
			(byte) 0xbf, (byte) 0xdf, (byte) 0x71, (byte) 0x29, (byte) 0xcd,
			(byte) 0x6c, (byte) 0x13, (byte) 0x64, (byte) 0x9b, (byte) 0x63,
			(byte) 0x9d, (byte) 0xc0, (byte) 0x4b, (byte) 0xb7, (byte) 0xa5,
			(byte) 0x89, (byte) 0x5f, (byte) 0xb1, (byte) 0x17, (byte) 0xf4,
			(byte) 0xbc, (byte) 0xd3, (byte) 0x46, (byte) 0xcf, (byte) 0x37,
			(byte) 0x5e, (byte) 0x47, (byte) 0x94, (byte) 0xfa, (byte) 0xfc,
			(byte) 0x5b, (byte) 0x97, (byte) 0xfe, (byte) 0x5a, (byte) 0xac,
			(byte) 0x3c, (byte) 0x4c, (byte) 0x03, (byte) 0x35, (byte) 0xf3,
			(byte) 0x23, (byte) 0xb8, (byte) 0x5d, (byte) 0x6a, (byte) 0x92,
			(byte) 0xd5, (byte) 0x21, (byte) 0x44, (byte) 0x51, (byte) 0xc6,
			(byte) 0x7d, (byte) 0x39, (byte) 0x83, (byte) 0xdc, (byte) 0xaa,
			(byte) 0x7c, (byte) 0x77, (byte) 0x56, (byte) 0x05, (byte) 0x1b,
			(byte) 0xa4, (byte) 0x15, (byte) 0x34, (byte) 0x1e, (byte) 0x1c,
			(byte) 0xf8, (byte) 0x52, (byte) 0x20, (byte) 0x14, (byte) 0xe9,
			(byte) 0xbd, (byte) 0xdd, (byte) 0xe4, (byte) 0xa1, (byte) 0xe0,
			(byte) 0x8a, (byte) 0xf1, (byte) 0xd6, (byte) 0x7a, (byte) 0xbb,
			(byte) 0xe3, (byte) 0x40, (byte) 0x4f, };

	/**
	 * SBOX #4
	 */
	private static final byte[] S4 = { (byte) 0x70, (byte) 0x2c, (byte) 0xb3,
			(byte) 0xc0, (byte) 0xe4, (byte) 0x57, (byte) 0xea, (byte) 0xae,
			(byte) 0x23, (byte) 0x6b, (byte) 0x45, (byte) 0xa5, (byte) 0xed,
			(byte) 0x4f, (byte) 0x1d, (byte) 0x92, (byte) 0x86, (byte) 0xaf,
			(byte) 0x7c, (byte) 0x1f, (byte) 0x3e, (byte) 0xdc, (byte) 0x5e,
			(byte) 0x0b, (byte) 0xa6, (byte) 0x39, (byte) 0xd5, (byte) 0x5d,
			(byte) 0xd9, (byte) 0x5a, (byte) 0x51, (byte) 0x6c, (byte) 0x8b,
			(byte) 0x9a, (byte) 0xfb, (byte) 0xb0, (byte) 0x74, (byte) 0x2b,
			(byte) 0xf0, (byte) 0x84, (byte) 0xdf, (byte) 0xcb, (byte) 0x34,
			(byte) 0x76, (byte) 0x6d, (byte) 0xa9, (byte) 0xd1, (byte) 0x04,
			(byte) 0x14, (byte) 0x3a, (byte) 0xde, (byte) 0x11, (byte) 0x32,
			(byte) 0x9c, (byte) 0x53, (byte) 0xf2, (byte) 0xfe, (byte) 0xcf,
			(byte) 0xc3, (byte) 0x7a, (byte) 0x24, (byte) 0xe8, (byte) 0x60,
			(byte) 0x69, (byte) 0xaa, (byte) 0xa0, (byte) 0xa1, (byte) 0x62,
			(byte) 0x54, (byte) 0x1e, (byte) 0xe0, (byte) 0x64, (byte) 0x10,
			(byte) 0x00, (byte) 0xa3, (byte) 0x75, (byte) 0x8a, (byte) 0xe6,
			(byte) 0x09, (byte) 0xdd, (byte) 0x87, (byte) 0x83, (byte) 0xcd,
			(byte) 0x90, (byte) 0x73, (byte) 0xf6, (byte) 0x9d, (byte) 0xbf,
			(byte) 0x52, (byte) 0xd8, (byte) 0xc8, (byte) 0xc6, (byte) 0x81,
			(byte) 0x6f, (byte) 0x13, (byte) 0x63, (byte) 0xe9, (byte) 0xa7,
			(byte) 0x9f, (byte) 0xbc, (byte) 0x29, (byte) 0xf9, (byte) 0x2f,
			(byte) 0xb4, (byte) 0x78, (byte) 0x06, (byte) 0xe7, (byte) 0x71,
			(byte) 0xd4, (byte) 0xab, (byte) 0x88, (byte) 0x8d, (byte) 0x72,
			(byte) 0xb9, (byte) 0xf8, (byte) 0xac, (byte) 0x36, (byte) 0x2a,
			(byte) 0x3c, (byte) 0xf1, (byte) 0x40, (byte) 0xd3, (byte) 0xbb,
			(byte) 0x43, (byte) 0x15, (byte) 0xad, (byte) 0x77, (byte) 0x80,
			(byte) 0x82, (byte) 0xec, (byte) 0x27, (byte) 0xe5, (byte) 0x85,
			(byte) 0x35, (byte) 0x0c, (byte) 0x41, (byte) 0xef, (byte) 0x93,
			(byte) 0x19, (byte) 0x21, (byte) 0x0e, (byte) 0x4e, (byte) 0x65,
			(byte) 0xbd, (byte) 0xb8, (byte) 0x8f, (byte) 0xeb, (byte) 0xce,
			(byte) 0x30, (byte) 0x5f, (byte) 0xc5, (byte) 0x1a, (byte) 0xe1,
			(byte) 0xca, (byte) 0x47, (byte) 0x3d, (byte) 0x01, (byte) 0xd6,
			(byte) 0x56, (byte) 0x4d, (byte) 0x0d, (byte) 0x66, (byte) 0xcc,
			(byte) 0x2d, (byte) 0x12, (byte) 0x20, (byte) 0xb1, (byte) 0x99,
			(byte) 0x4c, (byte) 0xc2, (byte) 0x7e, (byte) 0x05, (byte) 0xb7,
			(byte) 0x31, (byte) 0x17, (byte) 0xd7, (byte) 0x58, (byte) 0x61,
			(byte) 0x1b, (byte) 0x1c, (byte) 0x0f, (byte) 0x16, (byte) 0x18,
			(byte) 0x22, (byte) 0x44, (byte) 0xb2, (byte) 0xb5, (byte) 0x91,
			(byte) 0x08, (byte) 0xa8, (byte) 0xfc, (byte) 0x50, (byte) 0xd0,
			(byte) 0x7d, (byte) 0x89, (byte) 0x97, (byte) 0x5b, (byte) 0x95,
			(byte) 0xff, (byte) 0xd2, (byte) 0xc4, (byte) 0x48, (byte) 0xf7,
			(byte) 0xdb, (byte) 0x03, (byte) 0xda, (byte) 0x3f, (byte) 0x94,
			(byte) 0x5c, (byte) 0x02, (byte) 0x4a, (byte) 0x33, (byte) 0x67,
			(byte) 0xf3, (byte) 0x7f, (byte) 0xe2, (byte) 0x9b, (byte) 0x26,
			(byte) 0x37, (byte) 0x3b, (byte) 0x96, (byte) 0x4b, (byte) 0xbe,
			(byte) 0x2e, (byte) 0x79, (byte) 0x8c, (byte) 0x6e, (byte) 0x8e,
			(byte) 0xf5, (byte) 0xb6, (byte) 0xfd, (byte) 0x59, (byte) 0x98,
			(byte) 0x6a, (byte) 0x46, (byte) 0xba, (byte) 0x25, (byte) 0x42,
			(byte) 0xa2, (byte) 0xfa, (byte) 0x07, (byte) 0x55, (byte) 0xee,
			(byte) 0x0a, (byte) 0x49, (byte) 0x68, (byte) 0x38, (byte) 0xa4,
			(byte) 0x28, (byte) 0x7b, (byte) 0xc9, (byte) 0xc1, (byte) 0xe3,
			(byte) 0xf4, (byte) 0xc7, (byte) 0x9e, };

	/**
	 * The expanded key
	 */
	private byte[] expandedKey = new byte[272];

	/**
	 * key size in bits
	 */
	private int n;

	/**
	 * Constructor.
	 * 
	 * @param modeName
	 *            the mode to use
	 * @param keySize
	 *            the key size in bits
	 */
	protected Camellia(String modeName, int keySize) {
		// set the key size
		this.keySize = keySize;
		// disallow changing the key size
		keySizeIsMutable = false;

		// set the mode
		try {
			setMode(modeName);
		} catch (NoSuchModeException e) {
			throw new RuntimeException("Internal error: could not find mode '"
					+ modeName + "'.");
		}
	}

	/**
	 * Constructor.
	 */
	public Camellia() {
		// allow setting of the key size during initialization
		keySizeIsMutable = true;
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>CamelliaKey</tt> or <tt>SecretKeySpec</tt>
	 * and whether the key size is within the specified range for Camellia. 128,
	 * 192 and 256 bit keys are allowed.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof CamelliaKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("Unsupported key.");
		}

		final int keyLen = key.getEncoded().length;

		if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
			throw new InvalidKeyException("invalid key size");
		}

		return keyLen << 3;
	}

	/**
	 * This method returns the blocksize the algorithm uses. It will be called
	 * by the padding scheme.
	 * 
	 * @return the used blocksize in <B>bytes</B>
	 */
	protected int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * This method initializes the block cipher with a given key for data
	 * encryption.
	 * 
	 * @param key
	 *            SecretKey to be used to encrypt data
	 * @param params
	 *            AlgorithmParamterSpec to be used with this algorithm
	 * @throws InvalidKeyException
	 *             if the given key is illegal for this cipher
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if ((key == null) || !(key instanceof CamelliaKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		byte[] keyBytes = key.getEncoded();
		if (keySizeIsMutable) {
			keySize = keyBytes.length << 3;
		} else if (keyBytes.length != keySize >> 3) {
			throw new InvalidKeyException(
					"key size does not match specified length");
		}
		keyExpansion(keyBytes);
	}

	/**
	 * This method initializes the block cipher with a given key for data
	 * decryption.
	 * 
	 * @param key
	 *            SecretKey to be used to decrypt data
	 * @param params
	 *            AlgorithmParamterSpec to be used with this algorithm
	 * @throws InvalidKeyException
	 *             if the given key is illegal for this cipher
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method implements the Camellia key expansion.
	 * 
	 * @param key
	 *            An array of bytes containing the key data
	 */
	private void keyExpansion(byte[] key) {
		byte[] t = new byte[64];
		int[] u = new int[20];
		int i;

		n = key.length << 3;

		if (n == 128) {
			for (i = 0; i < 16; i++) {
				t[i] = key[i];
			}
			for (i = 16; i < 32; i++) {
				t[i] = 0;
			}
		} else if (n == 192) {
			for (i = 0; i < 24; i++) {
				t[i] = key[i];
			}
			for (i = 24; i < 32; i++) {
				t[i] = (byte) ((key[i - 8] ^ 0xff) & 0xff);
			}
		} else if (n == 256) {
			for (i = 0; i < 32; i++) {
				t[i] = key[i];
			}
		}

		xorBlock(t, 0, t, 16, t, 32);

		camelliaFeistel(t, 32, SIGMA, 0, t, 40);
		camelliaFeistel(t, 40, SIGMA, 8, t, 32);

		xorBlock(t, 32, t, 0, t, 32);

		camelliaFeistel(t, 32, SIGMA, 16, t, 40);
		camelliaFeistel(t, 40, SIGMA, 24, t, 32);

		toIntArray(t, 0, u, 0);
		toIntArray(t, 32, u, 4);

		if (n == 128) {
			for (i = 0; i < 26; i += 2) {
				rotBlock(u, KIDX1[i + 0], KSFT1[i + 0], u, 16);
				rotBlock(u, KIDX1[i + 1], KSFT1[i + 1], u, 18);
				toByteArray(u, 16, expandedKey, i << 3);
			}
		} else {
			xorBlock(t, 32, t, 16, t, 48);

			camelliaFeistel(t, 48, SIGMA, 32, t, 56);
			camelliaFeistel(t, 56, SIGMA, 40, t, 48);

			toIntArray(t, 16, u, 8);
			toIntArray(t, 48, u, 12);

			for (i = 0; i < 34; i += 2) {
				rotBlock(u, KIDX2[i + 0], KSFT2[i + 0], u, 16);
				rotBlock(u, KIDX2[i + 1], KSFT2[i + 1], u, 18);
				toByteArray(u, 16, expandedKey, i << 3);
			}
		}
	}

	/**
	 * This method encrypts a single block of data. The array <tt>in</tt> must
	 * contain a whole block starting at <tt>inOffset</tt> and <tt>out</tt> must
	 * be large enough to hold an encrypted block starting at <tt>outOffset</tt>
	 * .
	 * 
	 * @param input
	 *            array of bytes containing the plaintext to be encrypted
	 * @param inOff
	 *            index in array in, where the plaintext block starts
	 * @param output
	 *            array of bytes which will contain the ciphertext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the ciphertext block will start
	 */
	protected void singleBlockEncrypt(final byte[] input, final int inOff,
			byte[] output, final int outOff) {
		int i;

		xorBlock(input, inOff, expandedKey, 0, output, outOff);

		for (i = 0; i < 3; i++) {
			camelliaFeistel(output, outOff, expandedKey, 16 + (i << 4), output,
					outOff + 8);
			camelliaFeistel(output, outOff + 8, expandedKey, 24 + (i << 4),
					output, outOff);
		}

		camelliaFLlayer(output, outOff, expandedKey, 64, expandedKey, 72);

		for (i = 0; i < 3; i++) {
			camelliaFeistel(output, outOff, expandedKey, 80 + (i << 4), output,
					outOff + 8);
			camelliaFeistel(output, outOff + 8, expandedKey, 88 + (i << 4),
					output, outOff);
		}

		camelliaFLlayer(output, outOff, expandedKey, 128, expandedKey, 136);

		for (i = 0; i < 3; i++) {
			camelliaFeistel(output, outOff, expandedKey, 144 + (i << 4),
					output, outOff + 8);
			camelliaFeistel(output, outOff + 8, expandedKey, 152 + (i << 4),
					output, outOff);
		}

		if (n == 128) {
			swapHalves(output, outOff);
			xorBlock(output, outOff, expandedKey, 192, output, outOff);
		} else {
			camelliaFLlayer(output, outOff, expandedKey, 192, expandedKey, 200);

			for (i = 0; i < 3; i++) {
				camelliaFeistel(output, outOff + 0, expandedKey,
						208 + (i << 4), output, outOff + 8);
				camelliaFeistel(output, outOff + 8, expandedKey,
						216 + (i << 4), output, outOff);
			}

			swapHalves(output, outOff);
			xorBlock(output, outOff, expandedKey, 256, output, outOff);
		}
	}

	/**
	 * This method decrypts a single block of data. The array <tt>in</tt> must
	 * contain a whole block starting at <tt>inOffset</tt> and <tt>out</tt> must
	 * be large enough to hold an encrypted block starting at <tt>outOffset</tt>
	 * .
	 * 
	 * @param input
	 *            array of bytes containig the ciphertext to be decrypted
	 * @param inOff
	 *            index in array in, where the ciphertext block starts
	 * @param output
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the plaintext block will start
	 */
	protected void singleBlockDecrypt(final byte[] input, final int inOff,
			byte[] output, final int outOff) {
		int i;

		if (n == 128) {
			xorBlock(input, inOff, expandedKey, 192, output, outOff);
		} else {
			xorBlock(input, inOff, expandedKey, 256, output, outOff);

			for (i = 2; i >= 0; i--) {
				camelliaFeistel(output, outOff, expandedKey, 216 + (i << 4),
						output, outOff + 8);
				camelliaFeistel(output, outOff + 8, expandedKey,
						208 + (i << 4), output, outOff);
			}

			camelliaFLlayer(output, outOff, expandedKey, 200, expandedKey, 192);
		}

		for (i = 2; i >= 0; i--) {
			camelliaFeistel(output, outOff, expandedKey, 152 + (i << 4),
					output, outOff + 8);
			camelliaFeistel(output, outOff + 8, expandedKey, 144 + (i << 4),
					output, outOff);
		}

		camelliaFLlayer(output, outOff, expandedKey, 136, expandedKey, 128);

		for (i = 2; i >= 0; i--) {
			camelliaFeistel(output, outOff, expandedKey, 88 + (i << 4), output,
					outOff + 8);
			camelliaFeistel(output, outOff + 8, expandedKey, 80 + (i << 4),
					output, outOff);
		}

		camelliaFLlayer(output, outOff, expandedKey, 72, expandedKey, 64);

		for (i = 2; i >= 0; i--) {
			camelliaFeistel(output, outOff, expandedKey, 24 + (i << 4), output,
					outOff + 8);
			camelliaFeistel(output, outOff + 8, expandedKey, 16 + (i << 4),
					output, outOff);
		}

		swapHalves(output, outOff);
		xorBlock(output, outOff, expandedKey, 0, output, outOff);
	}

	// //////////////////////////////////////////////////////////////////////////////
	// CAMELLIA PRIMITIVES //
	// //////////////////////////////////////////////////////////////////////////////

	/**
	 * Compute the XOR of two 16 byte blocks.
	 * 
	 * @param x
	 *            the array containing the first block
	 * @param offx
	 *            the offset where the first block starts
	 * @param y
	 *            the array containing the second block
	 * @param offy
	 *            the offset where the second block starts
	 * @param z
	 *            the array containing the result
	 * @param offz
	 *            the offset where the result starts
	 */
	private static void xorBlock(byte[] x, int offx, byte[] y, int offy,
			byte[] z, int offz) {
		for (int i = 15; i >= 0; i--) {
			z[offz++] = (byte) (x[offx++] ^ y[offy++]);
		}
	}

	private static void rotBlock(int[] x, int offx, int n, int[] y, int offy) {
		final int r = n & 0x1f;
		if (r != 0) {
			y[offy] = (x[offx + (((n >>> 5)) & 3)] << r)
					| (x[offx + (((n >>> 5) + 1) & 3)] >>> (32 - r));
			y[offy + 1] = (x[offx + (((n >>> 5) + 1) & 3)] << r)
					| (x[offx + (((n >>> 5) + 2) & 3)] >>> (32 - r));
		} else {
			y[offy] = x[offx + (((n >>> 5)) & 3)];
			y[offy + 1] = x[offx + (((n >>> 5) + 1) & 3)];
		}
	}

	/**
	 * Swap the two halves of a 16 byte block contained in a byte array.
	 * 
	 * @param x
	 *            the byte array containing the block
	 * @param offx
	 *            the offset where the block starts
	 */
	private static void swapHalves(byte[] x, int offx) {
		byte t;

		for (int i = 0; i < 8; i++, offx++) {
			t = x[offx];
			x[offx] = x[offx + 8];
			x[offx + 8] = t;
		}
	}

	private static void camelliaFeistel(byte[] x, int offx, byte[] k, int offk,
			byte[] y, int offy) {

		byte[] t = new byte[8];

		t[0] = S1[(x[offx++] ^ k[offk++]) & 0xff];
		t[1] = S2[(x[offx++] ^ k[offk++]) & 0xff];
		t[2] = S3[(x[offx++] ^ k[offk++]) & 0xff];
		t[3] = S4[(x[offx++] ^ k[offk++]) & 0xff];
		t[4] = S2[(x[offx++] ^ k[offk++]) & 0xff];
		t[5] = S3[(x[offx++] ^ k[offk++]) & 0xff];
		t[6] = S4[(x[offx++] ^ k[offk++]) & 0xff];
		t[7] = S1[(x[offx] ^ k[offk]) & 0xff];

		y[offy++] ^= t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
		y[offy++] ^= t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
		y[offy++] ^= t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
		y[offy++] ^= t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
		y[offy++] ^= t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
		y[offy++] ^= t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
		y[offy++] ^= t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
		y[offy] ^= t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
	}

	private static void camelliaFLlayer(byte[] x, int offx, byte[] kl,
			int offkl, byte[] kr, int offkr) {

		int[] t = new int[4];
		int[] u = new int[4];
		int[] v = new int[4];

		toIntArray(x, offx, t, 0);
		toIntArray(kl, offkl, u, 0);
		toIntArray(kr, offkr, v, 0);

		t[1] ^= ((t[0] & u[0]) << 1) | ((t[0] & u[0]) >>> 31);
		t[0] ^= t[1] | u[1];
		t[2] ^= t[3] | v[1];
		t[3] ^= ((t[2] & v[0]) << 1) | ((t[2] & v[0]) >>> 31);

		toByteArray(t, 0, x, offx);
	}

	/**
	 * Convert a 16 byte block into an int array of length 4.
	 * 
	 * @param input
	 *            the byte array containing the block
	 * @param inOff
	 *            the offset where the block starts
	 * @param output
	 *            the output array
	 * @param outOff
	 *            the offset where the output starts
	 */
	private static void toIntArray(byte[] input, int inOff, int[] output,
			int outOff) {
		for (int i = 3; i >= 0; i--, inOff += 4, outOff += 1) {
			output[outOff] = BigEndianConversions.OS2IP(input, inOff);
		}
	}

	/**
	 * Convert 4 integers contained in an int array into a 16 byte block
	 * contained in a byte array.
	 * 
	 * @param input
	 *            the int array
	 * @param inOff
	 *            the offset where the 4 integers start
	 * @param output
	 *            the output array
	 * @param outOff
	 *            the offset where the block starts
	 */
	private static void toByteArray(int[] input, int inOff, byte[] output,
			int outOff) {
		for (int i = 3; i >= 0; i--, inOff++, outOff += 4) {
			BigEndianConversions.I2OSP(input[inOff], output, outOff);
		}
	}

}
