package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.feistel.FeistelKey;

public class FeistelKeyCreator 
	   extends MultiIntKeyCreator<FeistelKey> {
	
	private static final long serialVersionUID = -5831483180721711993L;
	
	private static final String[] methods = new String[]
			{
				"English Passphrase",
				"Manual Shifts"
			};

	public FeistelKeyCreator() 
	{
		super(methods, "Enter subkey: ");
	}

	protected FeistelKey extract(String phrase)
	{
		return new FeistelKey(this.alphabet,this.alphabet.convertTo(phrase.toCharArray(), 0, phrase.length()));
	}

	protected FeistelKey extract(int[] arr)
	{
		byte[] bytes = new byte[arr.length];
		for(int i = 0; i < arr.length; i++)
			bytes[i] = (byte) arr[i];
		return new FeistelKey(this.alphabet, bytes);
	}
	
}
