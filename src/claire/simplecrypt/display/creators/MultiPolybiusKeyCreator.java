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
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.Border;

import claire.simplecrypt.ciphers.fraction.MultiPolybiusKey;
import claire.simplecrypt.ciphers.fraction.PolybiusKey;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TablePane;
import claire.util.encoding.EncodingUtil;
import claire.util.memory.array.Memory;
import claire.util.memory.util.Pointer;

public class MultiPolybiusKeyCreator
	   extends KeyCreatorPanel<MultiPolybiusKey>
	   implements ActionListener {

	private static final long serialVersionUID = -5831483180721711993L;
	private static final Border shiftBorder = DisplayHelper.uniformBorder(3);

	private final Memory<PolybiusField> keys = new Memory<PolybiusField>(PolybiusField.class, 2);
	private final JLabel size = new JLabel();
	private final JScrollPane keypane = new JScrollPane(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	private final TablePane keytable = new TablePane();;
	
	private int x, y;
	
	public void initialize()
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		x = PolybiusKey.getRow(alphabet.getID());
		y = PolybiusKey.getCol(alphabet.getID());
		keytable.newRow();
		keytable.newCol(size);
		JButton add = new JButton("Add Shift");
		add.addActionListener(this);
		keytable.newCol(DisplayHelper.nestBorderWide(add, border));
		keytable.newRow();
		PolybiusField field = new PolybiusField(this, keys.preallocate());
		DisplayHelper.addBorder(field, shiftBorder);
		keys.allocate(field);
		keytable.newCol(field, 2);
		keypane.setViewportView(keytable);
		table.newRow(0.1D);
		table.newCol(DisplayHelper.nestBorderWide(keypane, border), 2);
	}

	public boolean error(Pointer<String> msg)
	{
		int len = keys.length();
		int next = -1;
		while(len-- > 0) {
			next = keys.getNextOccupied(next);
			PolybiusField f = keys.get(next);
			if(f.error(msg))
				return true;
		}
		return false;
	}

	public MultiPolybiusKey extract()
	{
		int i = 0,
		    next = -1,
		    len = keys.length();
		final byte[][] X = new byte[len][x],
					   Y = new byte[len][y];
		while(len-- > 0) {
			next = keys.getNextOccupied(next);
			PolybiusField f = keys.get(next);
			alphabet.convertTo(f.getXA(), 0, X[i  ], 0, x);
			alphabet.convertTo(f.getYA(), 0, Y[i++], 0, y);
		}
		return new MultiPolybiusKey(this.alphabet, X, Y);
	}
	
	protected void alphabetChanged() 
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		x = PolybiusKey.getRow(alphabet.getID());
		y = PolybiusKey.getCol(alphabet.getID());
		int next = -1, len = keys.length();
		while(len-- > 0) {
			next = keys.getNextOccupied(next);
			keys.get(next).update();
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
		keytable.newRow();
		PolybiusField field = new PolybiusField(this, keys.preallocate());
		DisplayHelper.addBorder(field, shiftBorder);
		keys.allocate(field);
		keytable.newCol(field, 2);
		this.revalidate();
	}
	
	private static final class PolybiusField 
						 extends JPanel
						 implements ActionListener
	{

		private static final long serialVersionUID = 7707755029891146061L;
		
		private final JLabel axl;
		private final JLabel ayl;
		private final JTextField ax = new JTextField(8);
		private final JTextField ay = new JTextField(8);
		private final MultiPolybiusKeyCreator owner;
		private final int pos;
		
		public PolybiusField(MultiPolybiusKeyCreator owner, int pos)
		{
			super(new GridBagLayout());
			this.pos = pos;
			this.owner = owner;
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.fill = GridBagConstraints.BOTH;
			gbc.gridy = 0;
			gbc.gridx = 0;
			this.add(axl = new JLabel("Enter X axis key (" + owner.x + " chars)"), gbc);
			gbc.gridx++;
			gbc.weightx = 0.1D;
			this.add(ax, gbc);
			gbc.gridy = 1;
			gbc.gridx = 0;
			this.add(ayl = new JLabel("Enter Y axis key (" + owner.y + " chars)"), gbc);
			gbc.gridx++;
			gbc.weightx = 0.1D;
			this.add(ay, gbc);
			gbc.gridx++;
			gbc.gridy = 0;
			gbc.gridheight = 2;
			gbc.weightx = 0.0D;
			JButton button = new JButton("Remove");
			button.addActionListener(this);
			JPanel panel = new JPanel(new BorderLayout());
			panel.add(button, BorderLayout.CENTER);
			this.add(panel, gbc);
		}

		public void actionPerformed(ActionEvent arg0)
		{
			owner.keys.free(pos);
			owner.keytable.remove(this);
			owner.revalidate();
		}
		
		public void update()
		{
			axl.setText("Enter X axis key (" + owner.x + " chars)");
			ayl.setText("Enter Y axis key (" + owner.y + " chars)");
		}
		
		public boolean error(Pointer<String> msg)
		{
			final String xt = ax.getText();
			final String yt = ay.getText();
			if(xt.length() != owner.x) {
				msg.set("Error, X-Axis key has an incorrect length");
				return true;
			}
			if(yt.length() != owner.y) {
				msg.set("Error, Y-Axis key has an incorrect length");
				return true;
			}
			if(!owner.alphabet.containsOnly(xt)) {
				msg.set("Error, X-Axis contains chars not in the alphabet");
				return true;
			}
			if(!owner.alphabet.containsOnly(yt)) {
				msg.set("Error, X-Axis contains chars not in the alphabet");
				return true;
			}
			if(EncodingUtil.repeatSlow(xt)) {
				msg.set("Error, X-Axis key has repeated characters");
				return true;
			}
			if(EncodingUtil.repeatSlow(yt)) {
				msg.set("Error, Y-Axis key has repeated characters");
				return true;
			}
			return false;
		}
		
		public char[] getXA()
		{
			return ax.getText().toCharArray();
		}
		
		public char[] getYA()
		{
			return ay.getText().toCharArray();
		}
		
	}
	
}
