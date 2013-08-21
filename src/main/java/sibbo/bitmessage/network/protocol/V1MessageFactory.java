package sibbo.bitmessage.network.protocol;

import java.util.Objects;

public class V1MessageFactory implements MessageFactory {

	@Override
	public InventoryVectorMessage createInventoryVectorMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Returns a new IGNORE message. The given data is probably ignored by the
	 * receiver.
	 * 
	 * @param data
	 *            Probably ignored by the receiver.
	 * @return A new ignore message.
	 */
	public MailMessage getIgnoreMailMessage(byte[] data) {
		Objects.requireNonNull(data, "data must not be null.");

		return new MailMessage(MessageEncoding.IGNORE, data, null, null, this);
	}

	/**
	 * Returns a new TRIVIAL message.
	 * 
	 * @param content
	 *            The message text.
	 * @return A new trivial message.
	 */
	public MailMessage getTrivialMailMessage(String content) {
		Objects.requireNonNull(content, "content must not be null.");

		return new MailMessage(MessageEncoding.TRIVIAL, null, null, content, this);
	}

	/**
	 * Returns a new SIMPLE message.
	 * 
	 * @param subject
	 *            The message subject.
	 * @param content
	 *            The message text.
	 * @return A new simple message.
	 */
	public MailMessage getSimpleMailMessage(String subject, String content) {
		Objects.requireNonNull(subject, "subject must not be null.");
		Objects.requireNonNull(content, "content must not be null.");

		return new MailMessage(MessageEncoding.SIMPLE, null, subject, content, this);
	}

}
