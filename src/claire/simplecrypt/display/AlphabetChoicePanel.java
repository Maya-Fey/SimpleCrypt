package claire.simplecrypt.display;

import javax.swing.JComboBox;

import claire.simplecrypt.data.Alphabet;
import claire.util.display.message.InformationCollectionPanel;
import claire.util.memory.util.Pointer;

public class AlphabetChoicePanel 
	   extends InformationCollectionPanel {

	private static final long serialVersionUID = -6468810411340420612L;
	
	private JComboBox<String> combo;
	
	public void initialize()
	{
		JComboBox<String> combo = new JComboBox<String>(Alphabet.alphastrings);
		this.add(combo);
		this.combo = combo;
	}

	public boolean error(Pointer<String> msg)
	{
		return false;
	}

	public boolean close(Pointer<String> msg)
	{
		return false;
	}
	
	public int getAlphabetID()
	{
		return combo.getSelectedIndex();
	}

	public int requestedHeight()
	{
		return 100;
	}
	
	public int requestedWidth()
	{
		return 240;
	}
	
}
