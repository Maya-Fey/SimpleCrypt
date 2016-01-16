package claire.simplecrypt.display;

import javax.swing.JComboBox;

import claire.simplecrypt.ciphers.CipherRegistry;
import claire.util.display.message.InformationCollectionPanel;
import claire.util.memory.util.Pointer;

public class CipherChoicePanel 
	   extends InformationCollectionPanel {

	private static final long serialVersionUID = -6468810411340420612L;
	
	private JComboBox<String> combo;
	
	public void initialize()
	{
		JComboBox<String> combo = new JComboBox<String>(CipherRegistry.names);
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
	
	public int getCipherID()
	{
		return combo.getSelectedIndex();
	}

}
