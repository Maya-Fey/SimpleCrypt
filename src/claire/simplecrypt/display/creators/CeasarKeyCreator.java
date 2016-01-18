package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.ceasar.CeasarKey;

public class CeasarKeyCreator 
	   extends IntKeyCreator<CeasarKey> {

	private static final long serialVersionUID = -5831483180721711993L;

	public CeasarKeyCreator()
	{
		super("Enter shift value: ");
	}
	
	public CeasarKey extract()
	{
		return new CeasarKey(this.getAlphabet(), this.getInt());
	}

}
