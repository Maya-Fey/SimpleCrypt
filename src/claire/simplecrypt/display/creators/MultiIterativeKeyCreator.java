package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.iterative.MultiIteratorKey;

public class MultiIterativeKeyCreator 
	   extends MultiIntKeyCreator<MultiIteratorKey> {
	
	private static final long serialVersionUID = -7227470386627829544L;
	
	private static final String[] methods = new String[]
			{
				"English Passphrase",
				"Manual Positions"
			};

	public MultiIterativeKeyCreator() 
	{
		super(methods, "Enter position: ");
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
