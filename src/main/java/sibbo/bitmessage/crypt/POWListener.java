package sibbo.bitmessage.crypt;

/**
 * Interface to notify objects if a pow-calculation is finished.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public interface POWListener {
	/**
	 * Informs the listener that the POW was finished by the given thread.
	 * 
	 * @param powWorker The thread that is finished.
	 */
	void powFinished(POWWorker powWorker);
}