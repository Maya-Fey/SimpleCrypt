package claire.simplecrypt.display;

import java.awt.GridBagConstraints;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.border.Border;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.util.display.DisplayHelper;
import claire.util.display.component.WrappedLabel;
import claire.util.display.layout.TableLayout;
import claire.util.display.message.InformationCollectionPanel;
import claire.util.memory.util.Pointer;

public abstract class KeyCreatorPanel<Key extends ISecret<?>> 
				extends InformationCollectionPanel 
				implements ItemListener {

	private static final long serialVersionUID = 3382806189819718872L;
	
	protected static final Border border = DisplayHelper.uniformBorder(6);

	protected final TableLayout table;
	
	protected Alphabet alphabet = Alphabet.SIMPLEAB;
	
	private final WrappedLabel ab;
	private final JComboBox<String> box;
	
	public KeyCreatorPanel() 
	{
		TableLayout table = this.table = new TableLayout(this, GridBagConstraints.BOTH);
		ab = new WrappedLabel(Alphabet.repFromID(alphabet.getID()));
		JLabel l1 = new JLabel("Alphabet: ");
		JComboBox<String> combo = this.box = new JComboBox<String>(Alphabet.names);
		combo.addItemListener(this);
		
		DisplayHelper.addBorder(ab, border);
		DisplayHelper.addBorder(l1, border);
		DisplayHelper.addBorder(combo, border);
		
		table.newRow();
		table.newCol(l1);
		table.newCol(ab);
		table.newRow();
		table.newCol(combo, 2);
		table.newRow(0.01D);
		table.newCol(new JLabel("----", SwingConstants.CENTER), 2);
	}
	
	public abstract Key extract();
	
	protected abstract void alphabetChanged();
	
	protected TableLayout getTable()
	{
		return this.table;
	}
	
	protected Alphabet getAlphabet()
	{
		return this.alphabet;
	}
	
	public void setAlphabet(Alphabet ab)
	{
		this.alphabet = ab;
		this.ab.setText(Alphabet.repFromID(ab.getID()));
		this.alphabetChanged();
	}
	
	public boolean close(Pointer<String> msg)
	{
		return false;
	}

	public void itemStateChanged(ItemEvent arg0)
	{
		if(arg0.getStateChange() == ItemEvent.SELECTED)
			setAlphabet(Alphabet.fromID(box.getSelectedIndex()));
	}
	
}
