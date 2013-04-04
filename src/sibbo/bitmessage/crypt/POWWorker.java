package sibbo.bitmessage.crypt;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.protocol.Util;

/**
 * A worker class to parallelize POW calculation.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class POWWorker implements Runnable {
	private static final Logger LOG = Logger.getLogger(POWWorker.class
			.getName());

	/**
	 * The time period in milliseconds to check if the pow calculation should be
	 * aborted.
	 */
	private static final int ROUND_TIME = 100;

	/** The collision quality that should be achieved. */
	private long target;

	/** The POW nonce. */
	private volatile long nonce;

	/** The initial hash value. */
	private byte[] initialHash;

	/** True if the calculation is running. */
	private volatile boolean running;

	/** A stop request can be made by setting this to true. */
	private volatile boolean stop;

	/** The listener to inform if we found the result. */
	private POWListener listener;

	/** The system load that should be created by this worker. */
	private float targetLoad;

	/** The increment that should be used for finding the next nonce. */
	private long increment;

	/**
	 * Creates a new POWWorker.
	 * 
	 * @param target The target collision quality.
	 * @param startNonce The nonce to start with.
	 * @param increment The step size. A POW worker calculates with: startNonce,
	 *            startNonce + increment, startNonce + 2 * increment...
	 * @param initialHash The hash of the message.
	 * @param listener The listener to inform if a result was found.
	 * @param targetLoad The system load that should be created by this worker.
	 */
	public POWWorker(long target, long startNonce, long increment,
			byte[] initialHash, POWListener listener, float targetLoad) {
		Objects.requireNonNull(listener, "listener must not be null.");

		this.target = target;
		this.nonce = startNonce;
		this.initialHash = initialHash;
		this.listener = listener;
		this.targetLoad = targetLoad;
		this.increment = increment;
	}

	/**
	 * Returns true if the worker is actually calculating the POW.
	 * 
	 * @return True if the worker is actually calculating the POW.
	 */
	public boolean isRunning() {
		return running;
	}

	/**
	 * Request the worker to stop.
	 */
	public void stop() {
		stop = true;
	}

	/**
	 * Returns the current nonce. Note that it can be wrong if isRunning()
	 * returns true or no success was reported.
	 * 
	 * @return The current nonce.
	 */
	public long getNonce() {
		return nonce;
	}

	/**
	 * Calculates the POW.
	 */
	@Override
	public void run() {
		running = true;

		int iterations = 100 * ROUND_TIME;
		long sleepTime = (long) (ROUND_TIME * (1 - targetLoad));
		long result = Long.MAX_VALUE;
		long nonce = this.nonce;

		float topLoad = targetLoad * 1.1f;
		float bottomLoad = targetLoad * 0.9f;

		while (!stop) {
			long ls = System.nanoTime();

			for (int i = 0; i < iterations; i++) {
				byte[] hash = Digest.sha512(Digest.sha512(Util.getBytes(nonce),
						initialHash));
				result = Util.getLong(hash);

				if (result <= target && result >= 0) {
					stop();
					this.nonce = nonce;
					listener.powFinished(this);
					break;
				}

				nonce += increment;
			}

			long lh = System.nanoTime();

			if (sleepTime > 0) {
				try {
					Thread.sleep(sleepTime);
				} catch (InterruptedException e) {
					LOG.log(Level.SEVERE, "Sleeping interrupted.", e);
					System.exit(1);
				}
			}

			long lf = System.nanoTime();

			float load = ((float) (lh - ls) / (float) (lf - ls));
			// System.out.println("Load: " + load);

			if (load > topLoad) {
				iterations -= iterations >> 8;
				// System.out.println("iterations: " + iterations);
			} else if (load < bottomLoad) {
				iterations += iterations >> 8;
				// System.out.println("iterations: " + iterations);
			}
		}

		running = false;
	}
	// public static void main(String[] args) {
	// byte[] initialHash = new byte[64];
	// Random r = new Random();
	// r.nextBytes(initialHash);
	//
	// POWWorker w = new POWWorker((long) Math.pow(2, 44), 0, 1, initialHash,
	// new POWListener() {
	// @Override
	// public void powFinished(POWWorker powWorker) {
	// System.out.println("finished");
	// System.out.println("Result: " + powWorker.getNonce());
	// }
	// }, 0.5f);
	//
	// w.run();
	// }
}