package claire.simplecrypt.display.creators;

import claire.simplecrypt.ciphers.iterative.IteratorKey;

public class IterativeKeyCreator 
	   extends IntKeyCreator<IteratorKey> {

	private static final long serialVersionUID = -5831483180721711993L;

	public IterativeKeyCreator()
	{
		super("Enter initial position: ");
	}
	
	public IteratorKey extract()
	{
		return new IteratorKey(this.getAlphabet(), this.getInt());
	}

}
