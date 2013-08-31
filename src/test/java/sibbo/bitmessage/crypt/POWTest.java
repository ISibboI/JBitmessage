package sibbo.bitmessage.crypt;

import java.text.DecimalFormat;
import java.util.Random;
import java.util.logging.Logger;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import sibbo.bitmessage.network.protocol.Util;

public class POWTest {
	private static final int CALCULATIONS = 100;

	/** Amount of different system load samples to test. */
	private static final int SYSTEM_LOAD_GRANULARITY = 25;

	@BeforeClass
	public static void setUpBeforeClass() {
		// Do some POW calculations to hopefully make the POW classes compile.
		POWCalculator pow = new POWCalculator(0x00000FFFFFFFFFFFL, new byte[64], 1);
		Logger.getLogger(POWTest.class.getName()).info(
				"Precalculations to hopefully make the POW classes compile: " + Util.getLong(pow.execute()));
	}

	/*
	 * Results: (100 Rounds) 274226ms
	 */
	@Ignore
	@Test
	public void testPOWDuration() {
		long start = System.currentTimeMillis();

		for (int i = 0; i < CALCULATIONS; i++) {
			Random r = new Random();
			byte[] hash = new byte[64];
			r.nextBytes(hash);

			POWCalculator pow = new POWCalculator(0x00000FFFFFFFFFFFL, hash, 1);
			pow.execute();
		}

		long end = System.currentTimeMillis();

		Logger.getLogger(getClass().getName()).info(
				"The calculation of " + CALCULATIONS + " POWs took " + (end - start) + "ms");
	}

	@Ignore
	@Test
	public void testShortMessageDuration() {
		long start = System.currentTimeMillis();

		for (int i = 0; i < CALCULATIONS; i++) {
			Random r = new Random();
			byte[] hash = new byte[64];
			r.nextBytes(hash);

			POWCalculator pow = new POWCalculator(CryptManager.getInstance().getPOWTarget(700), hash, 1);
			pow.execute();
		}

		long end = System.currentTimeMillis();

		Logger.getLogger(getClass().getName()).info(
				"The calculation of " + CALCULATIONS + " POWs took " + (end - start) / CALCULATIONS + "ms on average.");
	}

	@Ignore
	@Test
	public void testSystemLoad() {
		byte[] hash = new byte[64];
		long[] calculationTimes = new long[100];

		for (int i = 0; i < calculationTimes.length; i++) {
			long start = System.currentTimeMillis();

			POWCalculator pow = new POWCalculator(0x00000FFFFFFFFFFFL, hash, (i + 1f + calculationTimes.length / 5)
					/ (calculationTimes.length * 1.2f));
			pow.execute();

			long end = System.currentTimeMillis();

			calculationTimes[i] = end - start;
		}

		StringBuilder str = new StringBuilder();
		str.append("System load results:\n");

		for (int i = 0; i < calculationTimes.length; i++) {
			str.append(new DecimalFormat("0.000").format((i + 1f + calculationTimes.length / 5)
					/ (calculationTimes.length * 1.2f)));
			str.append(": ");
			str.append(calculationTimes[i]);
			str.append("ms\n");
		}

		Logger.getLogger(getClass().getName()).info(str.toString());
	}
}