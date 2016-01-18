package claire.simplecrypt.display;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.Border;

import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TablePane;
import claire.util.encoding.Base10;
import claire.util.memory.array.Memory;
import claire.util.memory.util.Pointer;

public class MultiCeasarKeyCreator 
	   extends KeyCreatorPanel<MultiCeasarKey> 
	   implements ActionListener {

	private static final long serialVersionUID = -5831483180721711993L;
	private static final Border shiftBorder = DisplayHelper.uniformBorder(3);
	
	private static final String[] methods = new String[]
		{
			"English Passphrase",
			"Manual Shifts"
		};

	private static final String notNum = "Entered text is not a number";
	private static final String outBounds = "Shift is must be less then the size of the alphabet.";
	
	private final JComboBox<String> combo = new JComboBox<String>(methods);
	private final JTextField field = new JTextField(8);
	private final JLabel size = new JLabel();
	private final JPanel main = new JPanel(new BorderLayout());
	
	//size.setText("Alphabet Size: " + this.getAlphabet().getLen());
	//DisplayHelper.addBorder(size, b);
	
	private TablePane shifttable;
	private JScrollPane shiftpane = new JScrollPane();
	private TablePane passpane = new TablePane();
	private Memory<ShiftField> shifts;
	
	public void initialize()
	{
		DisplayHelper.addBorder(size, border);
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		combo.addItemListener(this);
		JLabel l1 = new JLabel("Method: ");
		JLabel l2 = new JLabel("Passphrase: ");
		DisplayHelper.addBorder(l1, border);
		DisplayHelper.addBorder(l2, border);
		DisplayHelper.addBorder(combo, border);
		passpane.newRow();
		passpane.newCol(l2);
		passpane.newCol(DisplayHelper.nestBorderWide(field, border));
		
		table.newRow();
		table.newCol(l1);
		table.newCol(combo);
		table.newRow();
		table.newCol(main, 2);
		main.add(passpane, BorderLayout.CENTER);
	}

	public boolean error(Pointer<String> msg)
	{
		if(combo.getSelectedIndex() == 0) {
			char[] chars = field.getText().toCharArray();
			for(char c : chars)
				if(!this.alphabet.contains(c)) {
					msg.set("Passphrase contains characters not in selected alphabet.");
					return true;
				}
		} else {
			int len = shifts.length();
			int next = -1;
			while(len-- > 0) {
				next = shifts.getNextOccupied(next);
				ShiftField f = shifts.get(next);
				if(f.error(msg))
					return true;
			}
		}
		return false;
	}

	public MultiCeasarKey extract()
	{
		if(combo.getSelectedIndex() == 0)
			return new MultiCeasarKey(this.getAlphabet(), field.getText());
		else {
			int i = 0;
			int next = -1;
			int len = shifts.length();
			int[] arr = new int[len];
			while(len-- > 0) {
				next = shifts.getNextOccupied(next);
				ShiftField f = shifts.get(next);
				arr[i++] = f.getShift();
			}
			return new MultiCeasarKey(this.getAlphabet(), arr);
		}
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
	
	public void itemStateChanged(ItemEvent arg0)
	{
		if(arg0.getSource() == combo) 
			if(arg0.getStateChange() == ItemEvent.SELECTED) 
				if(combo.getSelectedIndex() == 0) {
					field.setText("");
					main.remove(shiftpane);
					table.newRow();
					table.newCol(main, 2);
					main.add(passpane, BorderLayout.CENTER);
					main.revalidate();
				} else {
					shifts = new Memory<ShiftField>(ShiftField.class, 2);
					TablePane pane = new TablePane();
					pane.newRow();
					pane.newCol(size);
					JButton add = new JButton("Add Shift");
					add.addActionListener(this);
					pane.newCol(DisplayHelper.nestBorderWide(add, border));
					pane.newRow();
					ShiftField field = new ShiftField(this, shifts.preallocate());
					DisplayHelper.addBorder(field, shiftBorder);
					shifts.allocate(field);
					pane.newCol(field, 2);
					shiftpane = new JScrollPane(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
					shiftpane.setViewportView(shifttable = pane);
					DisplayHelper.addBorder(shiftpane, border);
					main.remove(passpane);
					table.newRow(1.0D);
					table.newCol(main, 2);
					main.add(shiftpane, BorderLayout.CENTER);
					this.revalidate();
				}
			else;
		else
			super.itemStateChanged(arg0);
	}
	
	public void actionPerformed(ActionEvent arg0)
	{
		shifttable.newRow();
		ShiftField field = new ShiftField(this, shifts.preallocate());
		DisplayHelper.addBorder(field, shiftBorder);
		shifts.allocate(field);
		shifttable.newCol(field, 2);
		this.revalidate();
	}
	
	private static final class ShiftField 
						 extends JPanel
						 implements ActionListener
	{

		private static final long serialVersionUID = 7707755029891146061L;
		
		private final JTextField shift = new JTextField(8);
		private final MultiCeasarKeyCreator owner;
		private final int pos;
		
		public ShiftField(MultiCeasarKeyCreator owner, int pos)
		{
			super(new GridBagLayout());
			this.pos = pos;
			this.owner = owner;
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.fill = GridBagConstraints.BOTH;
			gbc.gridy = 0;
			gbc.gridx = 0;
			this.add(new JLabel("Enter Shift: "), gbc);
			gbc.gridx++;
			gbc.weightx = 0.1D;
			this.add(shift, gbc);
			JButton button = new JButton("Remove");
			button.addActionListener(this);
			JPanel panel = new JPanel(new BorderLayout());
			panel.add(button, BorderLayout.CENTER);
			gbc.gridx++;
			gbc.weightx = 0.0D;
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
			if(!Base10.isBase10(shift.getText())) {
				p.set(notNum);
				return true;
			}
			if(Base10.stringToInt(shift.getText()) >= owner.getAlphabet().getLen()) {
				p.set(outBounds);
				return true;
			}
			return false;
		}
		
		public int getShift()
		{
			return Base10.stringToInt(shift.getText());
		}
		
	}
	
}
