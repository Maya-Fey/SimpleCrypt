package claire.simplecrypt.display;

import javax.swing.JPanel;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.util.memory.util.Pointer;

public abstract class KeyCreatorPanel<Key extends ISecret<Key>> 
				extends JPanel {

	private static final long serialVersionUID = 3382806189819718872L;

	protected Alphabet alphabet = Alphabet.SIMPLEAB;
	
	public KeyCreatorPanel() {}
	
	public abstract void initialize();
	public abstract boolean error(Pointer<String> msg);
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
	
}
