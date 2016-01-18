package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;

public class MultiCeasarKeyCreator 
	   extends MultiIntKeyCreator<MultiCeasarKey> {
	
	private static final long serialVersionUID = -5831483180721711993L;
	
	private static final String[] methods = new String[]
			{
				"English Passphrase",
				"Manual Shifts"
			};

	public MultiCeasarKeyCreator() 
	{
		super(methods, "Enter shift: ");
	}

	protected MultiCeasarKey extract(String phrase)
	{
		return new MultiCeasarKey(this.alphabet, phrase);
	}

	protected MultiCeasarKey extract(int[] arr)
	{
		return new MultiCeasarKey(this.alphabet, arr);
	}
	
}
