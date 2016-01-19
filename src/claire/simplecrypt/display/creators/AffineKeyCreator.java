package claire.simplecrypt.display.creators;

import javax.swing.JLabel;
import javax.swing.JTextField;

import claire.simplecrypt.ciphers.mathematical.AffineKey;
import claire.util.display.DisplayHelper;
import claire.util.encoding.Base10;
import claire.util.math.MathHelper;
import claire.util.memory.util.Pointer;

public class AffineKeyCreator 
	   extends KeyCreatorPanel<AffineKey> {

	private static final long serialVersionUID = -5831483180721711993L;

	private static final String notNum = "Entered text in one or both fields is not a number.";
	private static final String outBounds = "Both numbers must be less then the size of the alphabet.";
	private static final String coprime = "Multiplier must be coprime to alphabet length.";
	private final JTextField fieldm = new JTextField(4);
	private final JTextField fields = new JTextField(4);
	private final JLabel size = new JLabel();
	private final JLabel l1 = new JLabel("Enter multiplier: ");
	private final JLabel l2 = new JLabel("Enter shift: ");
	
	public void initialize()
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		DisplayHelper.addBorder(l1, border);
		DisplayHelper.addBorder(l2, border);
		DisplayHelper.addBorder(size, border);
		table.newRow();
		table.newCol(size, 2);
		table.newRow();
		table.newCol(l1);
		table.newCol(DisplayHelper.nestBorderWide(fieldm, border));
		table.newRow();
		table.newCol(l2);
		table.newCol(DisplayHelper.nestBorderWide(fields, border));
	}

	public boolean error(Pointer<String> msg)
	{
		final int len = alphabet.getLen();
		final int m = Base10.stringToInt(fieldm.getText());
		if(!Base10.isBase10(fieldm.getText()) || !Base10.isBase10(fields.getText())) {
			msg.set(notNum);
			return true;
		}
		if(m >= len) {
			msg.set(outBounds);
			return true;
		}
		if(Base10.stringToInt(fields.getText()) >= len) {
			msg.set(outBounds);
			return true;
		}
		if(MathHelper.gcd(m, alphabet.getLen()) != 1) {
			msg.set(coprime);
			return true;
		}
		return false;
	}
	
	public AffineKey extract()
	{
		final int m = Base10.stringToInt(fieldm.getText());
		return new AffineKey(this.alphabet, Base10.stringToInt(fields.getText()), m, MathHelper.modular_inverse(m, alphabet.getLen()));
	}

	protected void alphabetChanged() 
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
	}
	
	public int requestedHeight()
	{
		return 261;
	}
	
	public int requestedWidth()
	{
		return 464;
	}

}
