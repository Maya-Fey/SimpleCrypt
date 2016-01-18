package claire.simplecrypt.display.creators;

import javax.swing.JLabel;
import javax.swing.JTextField;

import claire.simplecrypt.standards.ISecret;
import claire.util.display.DisplayHelper;
import claire.util.encoding.Base10;
import claire.util.memory.util.Pointer;

public abstract class IntKeyCreator<Key extends ISecret<?>> 
	   			extends KeyCreatorPanel<Key> {

	private static final long serialVersionUID = -5831483180721711993L;

	private static final String notNum = "Entered text is not a number";
	private static final String outBounds = "Shift is must be less then the size of the alphabet.";
	
	private final JTextField field = new JTextField(4);
	private final JLabel size = new JLabel();
	private final JLabel l1;
	
	public IntKeyCreator(String text)
	{
		l1 = new JLabel(text);
	}
	
	public void initialize()
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		DisplayHelper.addBorder(l1, border);
		DisplayHelper.addBorder(size, border);
		table.newRow();
		table.newCol(size, 2);
		table.newRow();
		table.newCol(l1);
		table.newCol(DisplayHelper.nestBorderWide(field, border));
	}

	public boolean error(Pointer<String> msg)
	{
		if(!Base10.isBase10(field.getText())) {
			msg.set(notNum);
			return true;
		}
		if(Base10.stringToInt(field.getText()) >= this.getAlphabet().getLen()) {
			msg.set(outBounds);
			return true;
		}
		return false;
	}
	
	protected int getInt()
	{
		return Base10.stringToInt(field.getText());
	}

	protected void alphabetChanged() 
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
	}
	
	public int requestedHeight()
	{
		return 243;
	}
	
	public int requestedWidth()
	{
		return 432;
	}

}
