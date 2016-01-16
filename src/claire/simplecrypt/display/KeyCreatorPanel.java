package claire.simplecrypt.display;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.util.display.message.InformationCollectionPanel;
import claire.util.memory.util.Pointer;

public abstract class KeyCreatorPanel<Key extends ISecret<?>> 
				extends InformationCollectionPanel {

	private static final long serialVersionUID = 3382806189819718872L;

	protected Alphabet alphabet = Alphabet.SIMPLEAB;
	
	public KeyCreatorPanel() {}
	
	public abstract Key extract();
	
	protected abstract void alphabetChanged();
	
	protected Alphabet getAlphabet()
	{
		return this.alphabet;
	}
	
	public void setAlphabet(Alphabet ab)
	{
		this.alphabet = ab;
		this.alphabetChanged();
	}
	
	public boolean close(Pointer<String> msg)
	{
		return true;
	}
	
}
