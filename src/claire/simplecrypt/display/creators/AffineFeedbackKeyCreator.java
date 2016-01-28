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

import claire.simplecrypt.ciphers.feedback.AffineFeedbackKey;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TablePane;
import claire.util.encoding.Base10;
import claire.util.math.MathHelper;
import claire.util.memory.array.Memory;
import claire.util.memory.util.Pointer;

public class AffineFeedbackKeyCreator
	   extends KeyCreatorPanel<AffineFeedbackKey>
	   implements ActionListener {

	private static final long serialVersionUID = -5831483180721711993L;
	private static final Border shiftBorder = DisplayHelper.uniformBorder(3);

	private static final String notNum = "Entered text in one or both fields is not a number.";
	private static final String outBounds = "Both numbers must be less then the size of the alphabet.";
	private static final String coprime = "Multiplier must be coprime to alphabet length.";
	
	private final Memory<AffineField> shifts = new Memory<AffineField>(AffineField.class, 2);
	private final JLabel size = new JLabel();
	private final JScrollPane shiftpane = new JScrollPane(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	private final TablePane shifttable = new TablePane();;
	
	
	public void initialize()
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		shifttable.newRow();
		shifttable.newCol(size);
		JButton add = new JButton("Add Shift");
		add.addActionListener(this);
		shifttable.newCol(DisplayHelper.nestBorderWide(add, border));
		shifttable.newRow();
		AffineField field = new AffineField(this, shifts.preallocate());
		DisplayHelper.addBorder(field, shiftBorder);
		shifts.allocate(field);
		shifttable.newCol(field, 2);
		shiftpane.setViewportView(shifttable);
		table.newRow(0.1D);
		table.newCol(DisplayHelper.nestBorderWide(shiftpane, border), 2);
	}

	public boolean error(Pointer<String> msg)
	{
		int len = shifts.length();
		int next = -1;
		while(len-- > 0) {
			next = shifts.getNextOccupied(next);
			AffineField f = shifts.get(next);
			if(f.error(msg))
				return true;
		}
		return false;
	}

	public AffineFeedbackKey extract()
	{
		int i = 0,
		    next = -1,
		    len = shifts.length();
		final int[] mul = new int[len],
		            add = new int[len];
		
		while(len-- > 0) {
			next = shifts.getNextOccupied(next);
			AffineField f = shifts.get(next);
			final int mula = f.getMul();
			add[i  ] = f.getShift();
			mul[i++] = mula;
		}
		return new AffineFeedbackKey(this.alphabet, add, mul);
	}
	
	protected void alphabetChanged() 
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
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
		shifttable.newRow();
		AffineField field = new AffineField(this, shifts.preallocate());
		DisplayHelper.addBorder(field, shiftBorder);
		shifts.allocate(field);
		shifttable.newCol(field, 2);
		this.revalidate();
	}
	
	private static final class AffineField 
						 extends JPanel
						 implements ActionListener
	{

		private static final long serialVersionUID = 7707755029891146061L;
		
		private final JTextField mul = new JTextField(8);
		private final JTextField shift = new JTextField(8);
		private final AffineFeedbackKeyCreator owner;
		private final int pos;
		
		public AffineField(AffineFeedbackKeyCreator owner, int pos)
		{
			super(new GridBagLayout());
			this.pos = pos;
			this.owner = owner;
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.fill = GridBagConstraints.BOTH;
			gbc.gridy = 0;
			gbc.gridx = 0;
			this.add(new JLabel("Enter multiplier: "), gbc);
			gbc.gridx++;
			gbc.weightx = 0.1D;
			this.add(mul, gbc);
			gbc.gridy = 1;
			gbc.gridx = 0;
			this.add(new JLabel("Enter shift: "), gbc);
			gbc.gridx++;
			gbc.weightx = 0.1D;
			this.add(shift, gbc);
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
			owner.shifts.free(pos);
			owner.shifttable.remove(this);
			owner.revalidate();
		}
		
		public boolean error(Pointer<String> p)
		{
			final int len = owner.alphabet.getLen();
			final int m = Base10.stringToInt(mul.getText());
			if(!Base10.isBase10(mul.getText()) || !Base10.isBase10(shift.getText())) {
				p.set(notNum);
				return true;
			}
			if(m >= len) {
				p.set(outBounds);
				return true;
			}
			if(Base10.stringToInt(shift.getText()) >= len) {
				p.set(outBounds);
				return true;
			}
			if(MathHelper.gcd(m, owner.alphabet.getLen()) != 1) {
				p.set(coprime);
				return true;
			}
			return false;
		}
		
		public int getShift()
		{
			return Base10.stringToInt(shift.getText());
		}
		
		public int getMul()
		{
			return Base10.stringToInt(mul.getText());
		}
		
	}
	
}
