package claire.simplecrypt.display.creators;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.Border;

import claire.simplecrypt.ciphers.substitution.MultiSubstitutionKey;
import claire.simplecrypt.ciphers.substitution.SubstitutionKey;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TablePane;
import claire.util.display.component.TextBox;
import claire.util.encoding.Hex;
import claire.util.memory.array.Memory;
import claire.util.memory.util.Pointer;

public class MultiSubstitutionKeyCreator
	   extends KeyCreatorPanel<MultiSubstitutionKey>
	   implements ActionListener {

	private static final long serialVersionUID = -5831483180721711993L;
	private static final Border subBorder = DisplayHelper.uniformBorder(3);

	private static final String missing = "Substitution alphabet is missing characters from actual alphabet.";
	private static final String outBounds = "Substitution alphabet must be equal in length to actual alphabet.";
	
	private final Memory<SubstitutionField> subs = new Memory<SubstitutionField>(SubstitutionField.class, 2);
	private final JLabel size = new JLabel();
	private final JScrollPane subpane = new JScrollPane(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	private final TablePane subtable = new TablePane();;
	
	private int cur;
	private boolean[] bools;
	
	public void initialize()
	{
		cur = alphabet.getLen();
		bools = new boolean[alphabet.getLen()];
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		subtable.newRow();
		subtable.newCol(size);
		JButton add = new JButton("Add Alphabet");
		add.addActionListener(this);
		subtable.newCol(DisplayHelper.nestBorderWide(add, border));
		subtable.newRow();
		SubstitutionField field = new SubstitutionField(this, subs.preallocate());
		DisplayHelper.addBorder(field, subBorder);
		subs.allocate(field);
		subtable.newCol(field, 2);
		subpane.setViewportView(subtable);
		table.newRow(0.1D);
		table.newCol(DisplayHelper.nestBorderWide(subpane, border), 2);
	}

	public boolean error(Pointer<String> msg)
	{
		int len = subs.length();
		int next = -1;
		while(len-- > 0) {
			next = subs.getNextOccupied(next);
			SubstitutionField f = subs.get(next);
			if(f.error(msg))
				return true;
		}
		return false;
	}

	public MultiSubstitutionKey extract()
	{
		int i = 0,
		    next = -1,
		    len = subs.length();
		final byte[][] key = new byte[len][];
		
		while(len-- > 0) {
			next = subs.getNextOccupied(next);
			SubstitutionField f = subs.get(next);
			key[i++] = f.getSub();
		}
		return new MultiSubstitutionKey(key, this.alphabet);
	}
	
	protected void alphabetChanged() 
	{
		final int len = alphabet.getLen();
		size.setText("Alphabet Size: " + len);
		if(cur > len) {
			bools = new boolean[alphabet.getLen()];
			cur = len;
			int slen = subs.length(),
				next = -1;
			while(slen-- > 0) {
				next = subs.getNextOccupied(next);
				SubstitutionField f = subs.get(next);
				f.update(len);
			}
		}
	}
	
	public int requestedHeight()
	{
		return 288;
	}
	
	public int requestedWidth()
	{
		return 518;
	}
	
	public void actionPerformed(ActionEvent arg0)
	{
		subtable.newRow();
		SubstitutionField field = new SubstitutionField(this, subs.preallocate());
		DisplayHelper.addBorder(field, subBorder);
		subs.allocate(field);
		subtable.newCol(field, 2);
		this.revalidate();
	}
	
	private static final class SubstitutionField 
						 extends JPanel
						 implements ActionListener
	{

		private static final long serialVersionUID = 7707755029891146061L;
		
		private final TextBox sub = new TextBox(8);
		private final MultiSubstitutionKeyCreator owner;
		private final int pos;
		
		private boolean[] bools;
		private byte[] bytes;
		
		public SubstitutionField(MultiSubstitutionKeyCreator owner, int pos)
		{
			super(new GridBagLayout());
			bools = owner.bools;
			bytes = new byte[owner.cur];
			this.pos = pos;
			this.owner = owner;
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.fill = GridBagConstraints.BOTH;
			gbc.gridy = 0;
			gbc.gridx = 0;
			this.add(new JLabel("Enter alphabet: "), gbc);
			gbc.gridx++;
			gbc.weightx = 0.1D;
			this.add(sub, gbc);
			gbc.gridx++;
			gbc.weightx = 0.0D;
			JButton button = new JButton("Remove");
			button.addActionListener(this);
			JPanel panel = new JPanel(new BorderLayout());
			panel.add(button, BorderLayout.CENTER);
			this.add(panel, gbc);
		}

		public void actionPerformed(ActionEvent arg0)
		{
			owner.subs.free(pos);
			owner.subtable.remove(this);
			owner.revalidate();
		}
		
		public void update(int nlen)
		{
			bytes = new byte[nlen];
			bools = owner.bools;
		}
		
		public boolean error(Pointer<String> p)
		{
			if(owner.alphabet.getLen() != sub.getText().length()) {
				p.set(outBounds);
				return true;
			}
			this.update();
			for(byte b : bytes)
				bools[b & 0xFF] = true;
			boolean a = true;
			for(int i = 0; i < owner.alphabet.getLen(); i++) {
				a &= bools[i];
				bools[i] = false;
			}
			if(!a) {
				p.set(missing);
				return true;
			}
			return false;
		}
		
		public byte[] getSub()
		{
			return bytes;
		}
		
		private void update()
		{
			if(sub.hasChanged()) {
				SubstitutionKey.fromChars(owner.alphabet, sub.getText(), bytes);
				sub.reset();
			}
		}
		
	}
	
}
