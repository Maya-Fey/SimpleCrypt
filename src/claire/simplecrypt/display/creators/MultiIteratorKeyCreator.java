package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.iterative.MultiIteratorKey;

public class MultiIteratorKeyCreator extends
		MultiIntKeyCreator<MultiIteratorKey> {
	
	private static final long serialVersionUID = -7227474234234234234L;	
	
	private static final String[] methods = new String[]
			{
				"English Passphrase",
				"Manual Iterators"
			};

	public MultiIteratorKeyCreator() 
	{
		super(methods, "Enter iterator: ");
	}

	protected MultiIteratorKey extract(String phrase)
	{
		return new MultiIteratorKey(this.alphabet, phrase);
	}

	protected MultiIteratorKey extract(int[] arr)
	{
		return new MultiIteratorKey(this.alphabet, arr);
	}

}
