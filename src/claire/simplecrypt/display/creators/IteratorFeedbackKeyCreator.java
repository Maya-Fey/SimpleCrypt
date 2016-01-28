package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.feedback.IteratorFeedbackKey;

public class IteratorFeedbackKeyCreator 
	   extends MultiIntKeyCreator<IteratorFeedbackKey> {
	
	private static final long serialVersionUID = -5831483180721711993L;
	
	private static final String[] methods = new String[]
			{
				"English Passphrase",
				"Manual Shifts"
			};

	public IteratorFeedbackKeyCreator() 
	{
		super(methods, "Enter shift: ");
	}

	protected IteratorFeedbackKey extract(String phrase)
	{
		return new IteratorFeedbackKey(this.alphabet, phrase);
	}

	protected IteratorFeedbackKey extract(int[] arr)
	{
		return new IteratorFeedbackKey(this.alphabet, arr);
	}
	
}
