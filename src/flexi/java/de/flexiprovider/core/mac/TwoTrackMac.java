/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mac;

import de.flexiprovider.api.Mac;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * This class extends the {@link Mac} class for providing the functionality of
 * the TTMAC(Two-Track-MAC) algorithm, as specified in <a
 * href="https://www.cosic.esat.kuleuven.be/nessie/deliverables/D20-v2.pdf"> the
 * version 2.0 of the NESSIE final reports</a>.
 * <p>
 * Any application dealing with MAC computation, uses the getInstance method of
 * the MAC class for creating a MAC object.
 * <p>
 * The FlexiProvider supports TTMAC computation with 32, 64, 96, 128 and 160-bit
 * output.
 * 
 * @author Paul Nguentcheu
 */
public abstract class TwoTrackMac extends Mac {

	/*
	 * Inner classes providing concrete implementations of TTMAC with a variety
	 * of output length.
	 */

	/**
	 * Buffer used to store bytes for processing
	 */
	private byte[] buffer = new byte[64];

	/**
	 * Internal buffer for processing
	 */
	private int[] x = new int[16];

	/**
	 * Counter for the bytes processed thus far
	 */
	private int count;

	/**
	 * Checks the last step of the mac computation
	 */
	private boolean last_step = false;

	/**
	 * stores the length of the MAC
	 */
	private int MAClength;

	/**
	 * keyinput stores the key as a five-byte word. state_l and state_r are
	 * needed for calculations
	 */
	private int[] keyinput = new int[5];
	private int[] state_l = new int[5];
	private int[] state_r = new int[5];

	/*
	 * Inner classes providing concrete implementations of TTMAC with a variety
	 * of output length.
	 */

	public static class TTMac32 extends TwoTrackMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "TwoTrackMac32";

		/**
		 * An alternative algorithm name.
		 */
		public static final String ALG_NAME2 = "TTmac32";

		public TTMac32() {
			super(32);
		}
	}

	public static class TTMac64 extends TwoTrackMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "TwoTrackMac64";

		/**
		 * An alternative algorithm name.
		 */
		public static final String ALG_NAME2 = "TTmac64";

		public TTMac64() {
			super(64);
		}
	}

	public static class TTMac96 extends TwoTrackMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "TwoTrackMac96";

		/**
		 * An alternative algorithm name.
		 */
		public static final String ALG_NAME2 = "TTmac96";

		public TTMac96() {
			super(96);
		}
	}

	public static class TTMac128 extends TwoTrackMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "TwoTrackMac128";

		/**
		 * An alternative algorithm name.
		 */
		public static final String ALG_NAME2 = "TTmac128";

		public TTMac128() {
			super(128);
		}
	}

	public static class TTMac160 extends TwoTrackMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "TwoTrackMac160";

		/**
		 * An alternative algorithm name.
		 */
		public static final String ALG_NAME2 = "TTmac160";

		/**
		 * A second alternative algorithm name.
		 */
		public static final String ALG_NAME3 = "TwoTrackMac";

		/**
		 * A third alternative algorithm name.
		 */
		public static final String ALG_NAME4 = "TTmac";

		public TTMac160() {
			super(160);
		}
	}

	/**
	 * Creates a new TTMac with the specified MAC length.
	 * 
	 * @param len
	 *            the bitlength of the MAC. Possible lengths are 32, 64, 96, 128
	 *            and 160.
	 */
	protected TwoTrackMac(int len) {
		if (len == 160 || len == 128 || len == 96 || len == 64 || len == 32) {
			MAClength = len;
		} else {
			MAClength = 160;
		}
	}

	/**
	 * Returns the length of the MAC in Bytes.
	 * 
	 * @return the length of the MAC.
	 */
	public int getMacLength() {
		return MAClength >> 3;
	}

	/**
	 * Initializes the Object with the given secret key for the following
	 * MAC-calculations.
	 * 
	 * @param key
	 *            the secret key with which this MAC object is initialized..
	 * @param params
	 *            the parameters are not used.
	 * @throws InvalidKeyException
	 *             if the key size is invalid.
	 */
	public void init(SecretKey key, AlgorithmParameterSpec params)
			throws InvalidKeyException {

		// array of bytes which will contain the keybytes
		byte[] myKey;
		// extract the keybytes
		myKey = key.getEncoded();

		if (myKey.length != 20) {
			throw new InvalidKeyException("invalid key size");
		}

		// Key in 5-byte word
		for (int i = 0; i <= 4; i++) {
			keyinput[i] = LittleEndianConversions.OS2IP(myKey, 4 * i);
		}

		for (int i = 0; i <= 4; i++) {
			state_l[i] = keyinput[i];
			state_r[i] = keyinput[i];
		}
	}

	/**
	 * Processes the given byte
	 * 
	 * @param b
	 *            the byte to be processed.
	 */
	public void update(byte b) {
		buffer[count & 63] = b;
		if ((count & 63) == 63) {
			x[0] = LittleEndianConversions.OS2IP(buffer, 0);
			x[1] = LittleEndianConversions.OS2IP(buffer, 4);
			x[2] = LittleEndianConversions.OS2IP(buffer, 8);
			x[3] = LittleEndianConversions.OS2IP(buffer, 12);
			x[4] = LittleEndianConversions.OS2IP(buffer, 16);
			x[5] = LittleEndianConversions.OS2IP(buffer, 20);
			x[6] = LittleEndianConversions.OS2IP(buffer, 24);
			x[7] = LittleEndianConversions.OS2IP(buffer, 28);
			x[8] = LittleEndianConversions.OS2IP(buffer, 32);
			x[9] = LittleEndianConversions.OS2IP(buffer, 36);
			x[10] = LittleEndianConversions.OS2IP(buffer, 40);
			x[11] = LittleEndianConversions.OS2IP(buffer, 44);
			x[12] = LittleEndianConversions.OS2IP(buffer, 48);
			x[13] = LittleEndianConversions.OS2IP(buffer, 52);
			x[14] = LittleEndianConversions.OS2IP(buffer, 56);
			x[15] = LittleEndianConversions.OS2IP(buffer, 60);
			processBlock();
		}
		count++;
	}

	/**
	 * Processes the given number of bytes, supplied in a byte array starting at
	 * the given position.
	 * 
	 * @param bytes
	 *            byte array containing the message to be processed
	 * @param offset
	 *            offset into the array to start from
	 * @param len
	 *            number of bytes to be processed.
	 */
	public void update(byte[] bytes, int offset, int len) {
		// fill up buffer
		while ((len > 0) & ((count & 63) != 0)) {
			update(bytes[offset++]);
			len--;
		}

		// return if nothing left to do
		if (len == 0) {
			return;
		}

		// process 64 byte blocks at once
		while (len >= 64) {
			x[0] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[1] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[2] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[3] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[4] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[5] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[6] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[7] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[8] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[9] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[10] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[11] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[12] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[13] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[14] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;
			x[15] = LittleEndianConversions.OS2IP(bytes, offset);
			offset += 4;

			count += 64;
			len -= 64;
			processBlock();
		}

		// process the remaining bytes
		if (len > 0) {
			System.arraycopy(bytes, offset, buffer, 0, len);
			count += len;
		}
	}

	/**
	 * Returns the calculated MAC value. After the MAC finally has been
	 * calculated, the MAC object is reset for further MAC computations.
	 * 
	 * @return the calculated MAC value.
	 */
	public byte[] doFinal() {
		// produce the final Mac computation
		byte[] mac = new byte[MAClength >> 3];

		padMessageMac();

		if (MAClength == 160) {
			LittleEndianConversions.I2OSP(state_l[0], mac, 0);
			LittleEndianConversions.I2OSP(state_l[1], mac, 4);
			LittleEndianConversions.I2OSP(state_l[2], mac, 8);
			LittleEndianConversions.I2OSP(state_l[3], mac, 12);
			LittleEndianConversions.I2OSP(state_l[4], mac, 16);
		} else if (MAClength == 128) {
			LittleEndianConversions.I2OSP(state_l[0] + state_l[1] + state_l[3],
					mac, 0);
			LittleEndianConversions.I2OSP(state_l[1] + state_l[2] + state_l[4],
					mac, 4);
			LittleEndianConversions.I2OSP(state_l[2] + state_l[3] + state_l[0],
					mac, 8);
			LittleEndianConversions.I2OSP(state_l[3] + state_l[4] + state_l[1],
					mac, 12);
		} else if (MAClength == 96) {
			LittleEndianConversions.I2OSP(state_l[0] + state_l[1] + state_l[3],
					mac, 0);
			LittleEndianConversions.I2OSP(state_l[1] + state_l[2] + state_l[4],
					mac, 4);
			LittleEndianConversions.I2OSP(state_l[2] + state_l[3] + state_l[0],
					mac, 8);
		} else if (MAClength == 64) {
			LittleEndianConversions.I2OSP(state_l[0] + state_l[1] + state_l[3],
					mac, 0);
			LittleEndianConversions.I2OSP(state_l[1] + state_l[2] + state_l[4],
					mac, 4);
		} else if (MAClength == 32) {
			LittleEndianConversions.I2OSP(state_l[0] + state_l[1] + state_l[2]
					+ state_l[3] + state_l[4], mac, 0);
		}

		// reset the engine to its initial state
		reset();

		return mac;
	}

	/**
	 * Resets the MAC for further use, maintaining the secret key that the MAC
	 * was initialized with.
	 */
	public void reset() {

		for (int i = 0; i <= 4; i++) {
			state_l[i] = keyinput[i];
			state_r[i] = keyinput[i];
		}
		count = 0;
		last_step = false;
	}

	/**
	 * This method performs the padding. A single 1-bit is appended and then
	 * 0-bits, until only 64 bits are left free in the final block to enter the
	 * total length of the entered message.
	 */
	private void padMessageMac() {
		// bit length = count * 8
		long len = count << 3;

		// do some padding
		update((byte) 0x80); // add single bit
		while ((count & 63) != 56) {
			update((byte) 0); // fill up with zeros
		}

		// convert byte buffer to int buffer.
		for (int i = 0; i < 14; i++) {
			x[i] = LittleEndianConversions.OS2IP(buffer, 4 * i);
		}
		x[14] = (int) (len & 0xffffffff); // add length
		x[15] = (int) ((len >>> 32) & 0xffffffff);
		last_step = true;
		processBlock();
	}

	/**
	 * Process a block of 64 bytes
	 */
	private synchronized void processBlock() {
		int Al, Bl, Cl, Dl, El;
		int Ar, Br, Cr, Dr, Er;
		int[] C = new int[5];
		int[] D = new int[5];

		if (!last_step) {
			Al = state_l[0];
			Bl = state_l[1];
			Cl = state_l[2];
			Dl = state_l[3];
			El = state_l[4];

			Ar = state_r[0];
			Br = state_r[1];
			Cr = state_r[2];
			Dr = state_r[3];
			Er = state_r[4];
		} else { // swap(L,R);
			Al = state_r[0];
			Bl = state_r[1];
			Cl = state_r[2];
			Dl = state_r[3];
			El = state_r[4];

			Ar = state_l[0];
			Br = state_l[1];
			Cr = state_l[2];
			Dr = state_l[3];
			Er = state_l[4];
		}

		// rounds 0-15 (left)
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[0], 11) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + F(Al, Bl, Cl) + x[1], 14) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + F(El, Al, Bl) + x[2], 15) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + F(Dl, El, Al) + x[3], 12) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + F(Cl, Dl, El) + x[4], 5) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[5], 8) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + F(Al, Bl, Cl) + x[6], 7) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + F(El, Al, Bl) + x[7], 9) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + F(Dl, El, Al) + x[8], 11) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + F(Cl, Dl, El) + x[9], 13) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[10], 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + F(Al, Bl, Cl) + x[11], 15) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + F(El, Al, Bl) + x[12], 6) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + F(Dl, El, Al) + x[13], 7) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + F(Cl, Dl, El) + x[14], 9) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[15], 8) + El;
		Cl = rotateLeft(Cl, 10);

		// rounds 0-15 (right)
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[5] + 0x50a28be6, 8) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + L(Ar, Br, Cr) + x[14] + 0x50a28be6, 9) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + L(Er, Ar, Br) + x[7] + 0x50a28be6, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + L(Dr, Er, Ar) + x[0] + 0x50a28be6, 11) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + L(Cr, Dr, Er) + x[9] + 0x50a28be6, 13) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[2] + 0x50a28be6, 15) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + L(Ar, Br, Cr) + x[11] + 0x50a28be6, 15) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + L(Er, Ar, Br) + x[4] + 0x50a28be6, 5) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + L(Dr, Er, Ar) + x[13] + 0x50a28be6, 7) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + L(Cr, Dr, Er) + x[6] + 0x50a28be6, 7) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[15] + 0x50a28be6, 8) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + L(Ar, Br, Cr) + x[8] + 0x50a28be6, 11) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + L(Er, Ar, Br) + x[1] + 0x50a28be6, 14) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + L(Dr, Er, Ar) + x[10] + 0x50a28be6, 14) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + L(Cr, Dr, Er) + x[3] + 0x50a28be6, 12) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[12] + 0x50a28be6, 6) + Er;
		Cr = rotateLeft(Cr, 10);

		// rounds 16-31 (left)
		El = rotateLeft(El + G(Al, Bl, Cl) + x[7] + 0x5a827999, 7) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + G(El, Al, Bl) + x[4] + 0x5a827999, 6) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + G(Dl, El, Al) + x[13] + 0x5a827999, 8) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + G(Cl, Dl, El) + x[1] + 0x5a827999, 13) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + G(Bl, Cl, Dl) + x[10] + 0x5a827999, 11) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + G(Al, Bl, Cl) + x[6] + 0x5a827999, 9) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + G(El, Al, Bl) + x[15] + 0x5a827999, 7) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + G(Dl, El, Al) + x[3] + 0x5a827999, 15) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + G(Cl, Dl, El) + x[12] + 0x5a827999, 7) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + G(Bl, Cl, Dl) + x[0] + 0x5a827999, 12) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + G(Al, Bl, Cl) + x[9] + 0x5a827999, 15) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + G(El, Al, Bl) + x[5] + 0x5a827999, 9) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + G(Dl, El, Al) + x[2] + 0x5a827999, 11) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + G(Cl, Dl, El) + x[14] + 0x5a827999, 7) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + G(Bl, Cl, Dl) + x[11] + 0x5a827999, 13) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + G(Al, Bl, Cl) + x[8] + 0x5a827999, 12) + Dl;
		Bl = rotateLeft(Bl, 10);

		// rounds 16-31 (right)
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[6] + 0x5c4dd124, 9) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + K(Er, Ar, Br) + x[11] + 0x5c4dd124, 13) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + K(Dr, Er, Ar) + x[3] + 0x5c4dd124, 15) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + K(Cr, Dr, Er) + x[7] + 0x5c4dd124, 7) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + K(Br, Cr, Dr) + x[0] + 0x5c4dd124, 12) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[13] + 0x5c4dd124, 8) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + K(Er, Ar, Br) + x[5] + 0x5c4dd124, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + K(Dr, Er, Ar) + x[10] + 0x5c4dd124, 11) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + K(Cr, Dr, Er) + x[14] + 0x5c4dd124, 7) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + K(Br, Cr, Dr) + x[15] + 0x5c4dd124, 7) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[8] + 0x5c4dd124, 12) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + K(Er, Ar, Br) + x[12] + 0x5c4dd124, 7) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + K(Dr, Er, Ar) + x[4] + 0x5c4dd124, 6) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + K(Cr, Dr, Er) + x[9] + 0x5c4dd124, 15) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + K(Br, Cr, Dr) + x[1] + 0x5c4dd124, 13) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[2] + 0x5c4dd124, 11) + Dr;
		Br = rotateLeft(Br, 10);

		// rounds 32-47 (left)
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[3] + 0x6ed9eba1, 11) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + H(Dl, El, Al) + x[10] + 0x6ed9eba1, 13) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + H(Cl, Dl, El) + x[14] + 0x6ed9eba1, 6) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + H(Bl, Cl, Dl) + x[4] + 0x6ed9eba1, 7) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + H(Al, Bl, Cl) + x[9] + 0x6ed9eba1, 14) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[15] + 0x6ed9eba1, 9) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + H(Dl, El, Al) + x[8] + 0x6ed9eba1, 13) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + H(Cl, Dl, El) + x[1] + 0x6ed9eba1, 15) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + H(Bl, Cl, Dl) + x[2] + 0x6ed9eba1, 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + H(Al, Bl, Cl) + x[7] + 0x6ed9eba1, 8) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[0] + 0x6ed9eba1, 13) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + H(Dl, El, Al) + x[6] + 0x6ed9eba1, 6) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + H(Cl, Dl, El) + x[13] + 0x6ed9eba1, 5) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + H(Bl, Cl, Dl) + x[11] + 0x6ed9eba1, 12) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + H(Al, Bl, Cl) + x[5] + 0x6ed9eba1, 7) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[12] + 0x6ed9eba1, 5) + Cl;
		Al = rotateLeft(Al, 10);

		// rounds 32-47 (right)
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[15] + 0x6d703ef3, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + H(Dr, Er, Ar) + x[5] + 0x6d703ef3, 7) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + H(Cr, Dr, Er) + x[1] + 0x6d703ef3, 15) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + H(Br, Cr, Dr) + x[3] + 0x6d703ef3, 11) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + H(Ar, Br, Cr) + x[7] + 0x6d703ef3, 8) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[14] + 0x6d703ef3, 6) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + H(Dr, Er, Ar) + x[6] + 0x6d703ef3, 6) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + H(Cr, Dr, Er) + x[9] + 0x6d703ef3, 14) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + H(Br, Cr, Dr) + x[11] + 0x6d703ef3, 12) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + H(Ar, Br, Cr) + x[8] + 0x6d703ef3, 13) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[12] + 0x6d703ef3, 5) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + H(Dr, Er, Ar) + x[2] + 0x6d703ef3, 14) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + H(Cr, Dr, Er) + x[10] + 0x6d703ef3, 13) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + H(Br, Cr, Dr) + x[0] + 0x6d703ef3, 13) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + H(Ar, Br, Cr) + x[4] + 0x6d703ef3, 7) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[13] + 0x6d703ef3, 5) + Cr;
		Ar = rotateLeft(Ar, 10);

		// rounds 48-63 (left)
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[1] + 0x8f1bbcdc, 11) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + K(Cl, Dl, El) + x[9] + 0x8f1bbcdc, 12) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + K(Bl, Cl, Dl) + x[11] + 0x8f1bbcdc, 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + K(Al, Bl, Cl) + x[10] + 0x8f1bbcdc, 15) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + K(El, Al, Bl) + x[0] + 0x8f1bbcdc, 14) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[8] + 0x8f1bbcdc, 15) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + K(Cl, Dl, El) + x[12] + 0x8f1bbcdc, 9) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + K(Bl, Cl, Dl) + x[4] + 0x8f1bbcdc, 8) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + K(Al, Bl, Cl) + x[13] + 0x8f1bbcdc, 9) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + K(El, Al, Bl) + x[3] + 0x8f1bbcdc, 14) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[7] + 0x8f1bbcdc, 5) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + K(Cl, Dl, El) + x[15] + 0x8f1bbcdc, 6) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + K(Bl, Cl, Dl) + x[14] + 0x8f1bbcdc, 8) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + K(Al, Bl, Cl) + x[5] + 0x8f1bbcdc, 6) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + K(El, Al, Bl) + x[6] + 0x8f1bbcdc, 5) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[2] + 0x8f1bbcdc, 12) + Bl;
		El = rotateLeft(El, 10);

		// rounds 48-63 (right)
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[8] + 0x7a6d76e9, 15) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + G(Cr, Dr, Er) + x[6] + 0x7a6d76e9, 5) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + G(Br, Cr, Dr) + x[4] + 0x7a6d76e9, 8) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + G(Ar, Br, Cr) + x[1] + 0x7a6d76e9, 11) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + G(Er, Ar, Br) + x[3] + 0x7a6d76e9, 14) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[11] + 0x7a6d76e9, 14) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + G(Cr, Dr, Er) + x[15] + 0x7a6d76e9, 6) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + G(Br, Cr, Dr) + x[0] + 0x7a6d76e9, 14) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + G(Ar, Br, Cr) + x[5] + 0x7a6d76e9, 6) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + G(Er, Ar, Br) + x[12] + 0x7a6d76e9, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[2] + 0x7a6d76e9, 12) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + G(Cr, Dr, Er) + x[13] + 0x7a6d76e9, 9) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + G(Br, Cr, Dr) + x[9] + 0x7a6d76e9, 12) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + G(Ar, Br, Cr) + x[7] + 0x7a6d76e9, 5) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + G(Er, Ar, Br) + x[10] + 0x7a6d76e9, 15) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[14] + 0x7a6d76e9, 8) + Br;
		Er = rotateLeft(Er, 10);

		// rounds 64-79 (left)
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[4] + 0xa953fd4e, 9) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + L(Bl, Cl, Dl) + x[0] + 0xa953fd4e, 15) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + L(Al, Bl, Cl) + x[5] + 0xa953fd4e, 5) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + L(El, Al, Bl) + x[9] + 0xa953fd4e, 11) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + L(Dl, El, Al) + x[7] + 0xa953fd4e, 6) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[12] + 0xa953fd4e, 8) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + L(Bl, Cl, Dl) + x[2] + 0xa953fd4e, 13) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + L(Al, Bl, Cl) + x[10] + 0xa953fd4e, 12) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + L(El, Al, Bl) + x[14] + 0xa953fd4e, 5) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + L(Dl, El, Al) + x[1] + 0xa953fd4e, 12) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[3] + 0xa953fd4e, 13) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + L(Bl, Cl, Dl) + x[8] + 0xa953fd4e, 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + L(Al, Bl, Cl) + x[11] + 0xa953fd4e, 11) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + L(El, Al, Bl) + x[6] + 0xa953fd4e, 8) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + L(Dl, El, Al) + x[15] + 0xa953fd4e, 5) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[13] + 0xa953fd4e, 6) + Al;
		Dl = rotateLeft(Dl, 10);

		// rounds 64-79 (right)
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[12], 8) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + F(Br, Cr, Dr) + x[15], 5) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + F(Ar, Br, Cr) + x[10], 12) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + F(Er, Ar, Br) + x[4], 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + F(Dr, Er, Ar) + x[1], 12) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[5], 5) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + F(Br, Cr, Dr) + x[8], 14) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + F(Ar, Br, Cr) + x[7], 6) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + F(Er, Ar, Br) + x[6], 8) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + F(Dr, Er, Ar) + x[2], 13) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[13], 6) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + F(Br, Cr, Dr) + x[14], 5) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + F(Ar, Br, Cr) + x[0], 15) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + F(Er, Ar, Br) + x[3], 13) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + F(Dr, Er, Ar) + x[9], 11) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[11], 11) + Ar;
		Dr = rotateLeft(Dr, 10);

		if (last_step) {
			int[] tmp = new int[5];

			tmp[0] = Al;
			tmp[1] = Bl;
			tmp[2] = Cl;
			tmp[3] = Dl;
			tmp[4] = El;

			Al = Ar;
			Bl = Br;
			Cl = Cr;
			Dl = Dr;
			El = Er;

			Ar = tmp[0];
			Br = tmp[1];
			Cr = tmp[2];
			Dr = tmp[3];
			Er = tmp[4];

			C[0] = Al - state_l[0];
			D[0] = Ar - state_r[0];
			C[1] = Bl - state_l[1];
			D[1] = Br - state_r[1];
			C[2] = Cl - state_l[2];
			D[2] = Cr - state_r[2];
			C[3] = Dl - state_l[3];
			D[3] = Dr - state_r[3];
			C[4] = El - state_l[4];
			D[4] = Er - state_r[4];

			state_l[0] = C[0] - D[0];
			state_l[1] = C[1] - D[1];
			state_l[2] = C[2] - D[2];
			state_l[3] = C[3] - D[3];
			state_l[4] = C[4] - D[4];
		} else {

			C[0] = Al - state_l[0];
			D[0] = Ar - state_r[0];
			C[1] = Bl - state_l[1];
			D[1] = Br - state_r[1];
			C[2] = Cl - state_l[2];
			D[2] = Cr - state_r[2];
			C[3] = Dl - state_l[3];
			D[3] = Dr - state_r[3];
			C[4] = El - state_l[4];
			D[4] = Er - state_r[4];

			state_l[0] = C[1] + C[4] - D[3];
			state_l[1] = C[2] - D[4];
			state_l[2] = C[3] - D[0];
			state_l[3] = C[4] - D[1];
			state_l[4] = C[0] - D[2];

			state_r[0] = C[3] - D[4];
			state_r[1] = C[4] + C[2] - D[0];
			state_r[2] = C[0] - D[1];
			state_r[3] = C[1] - D[2];
			state_r[4] = C[2] - D[3];
		}
	}

	/**
	 * Basic conversion functions
	 */
	private int F(int u, int v, int w) {
		return u ^ v ^ w;
	}

	private int G(int u, int v, int w) {
		return (u & v) | (~u & w);
	}

	private int H(int u, int v, int w) {
		return (u | ~v) ^ w;
	}

	private int K(int u, int v, int w) {
		return (u & w) | (v & ~w);
	}

	private int L(int u, int v, int w) {
		return u ^ (v | ~w);
	}

	private int rotateLeft(int x, int n) {
		return (x << n) | (x >>> (32 - n));
	}
}
