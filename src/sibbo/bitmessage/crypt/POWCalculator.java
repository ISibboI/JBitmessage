package sibbo.bitmessage.crypt;

import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.Util;

/**
 * Does the POW calculation, uses multiple threads.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class POWCalculator implements POWListener {
	private static final Logger LOG = Logger.getLogger(POWCalculator.class
			.getName());

	/** The amount of threads to use per CPU. */
	private static final int THREADS_PER_CPU = 1;

	/** The target collision quality. */
	private long target;

	/** The hash of the message. */
	private byte[] initialHash;

	/** The target system load created by the calculation. (Per CPU) */
	private float targetLoad;

	/** The worker that found a valid nonce. */
	private POWWorker finishedWorker;

	/**
	 * Creates a new POWCalculator.
	 * 
	 * @param target The target collision quality.
	 * @param initialHash The hash of the message.
	 * @param targetLoad The target system load created by the calculation. (Per
	 *            CPU)
	 */
	public POWCalculator(long target, byte[] initialHash, float targetLoad) {
		this.target = target;
		this.initialHash = initialHash;
		this.targetLoad = targetLoad;
	}

	/**
	 * Calculate the POW.<br />
	 * <b>WARNING: This can take a long time.</b>
	 */
	public synchronized byte[] execute() {
		POWWorker[] workers = new POWWorker[Runtime.getRuntime()
				.availableProcessors() * THREADS_PER_CPU];

		for (int i = 0; i < workers.length; i++) {
			workers[i] = new POWWorker(target, i, workers.length, initialHash,
					this, targetLoad / THREADS_PER_CPU);
			new Thread(workers[i], "POW Worker No. " + i).start();
		}

		try {
			wait();
		} catch (InterruptedException e) {
			LOG.log(Level.SEVERE, "Waiting interrupted!", e);
			System.exit(1);
		}

		for (POWWorker w : workers) {
			w.stop();
		}

		return Util.getBytes(finishedWorker.getNonce());
	}

	@Override
	public synchronized void powFinished(POWWorker powWorker) {
		if (finishedWorker == null) {
			finishedWorker = powWorker;
		}

		notifyAll();
	}
}