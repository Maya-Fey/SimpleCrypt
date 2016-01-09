package claire.simplecrypt.display;

import javax.swing.JLabel;
import javax.swing.JTextField;

import claire.simplecrypt.ciphers.ceasar.CeasarKey;
import claire.util.display.TableLayout;
import claire.util.encoding.Base10;
import claire.util.memory.util.Pointer;

public class CeasarKeyCreator 
	   extends KeyCreatorPanel<CeasarKey> {

	private static final long serialVersionUID = -5831483180721711993L;

	private static final String notNum = "Entered text is not a number";
	private static final String outBounds = "Shift is must be less then the size of the alphabet.";
	
	private final JTextField field = new JTextField(8);
	private final JLabel size = new JLabel();
	
	public void initialize()
	{
		TableLayout layout = new TableLayout(this);
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		layout.newRow();
		layout.newCol(size, 2);
		layout.newRow();
		layout.newCol(new JLabel("Enter Shift Value: "));
		layout.newCol(field);
	}

	public boolean error(Pointer<String> msg)
	{
		if(!Base10.isBase10(field.getText())) {
			msg.set(notNum);
			return true;
		}
		if(Base10.stringToInt(field.getText()) > this.getAlphabet().getLen()) {
			msg.set(outBounds);
			return true;
		}
		return false;
	}

	public CeasarKey extract()
	{
		return new CeasarKey(this.getAlphabet(), Base10.stringToInt(field.getText()));
	}

	protected void alphabetChanged() 
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
	}

}
