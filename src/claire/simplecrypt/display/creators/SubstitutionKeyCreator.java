package claire.simplecrypt.display.creators;

import javax.swing.JLabel;

import claire.simplecrypt.ciphers.substitution.SubstitutionKey;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TextBox;
import claire.util.memory.util.Pointer;

public class SubstitutionKeyCreator 
	   extends KeyCreatorPanel<SubstitutionKey> {

	private static final long serialVersionUID = -5831483180721711993L;

	private static final String missing = "Substitution alphabet is missing characters from actual alphabet.";
	private static final String outBounds = "Substitution alphabet must be equal in length to actual alphabet.";
	private final TextBox subs = new TextBox(4);
	private final JLabel size = new JLabel();
	private final JLabel l1 = new JLabel("Enter substitutions: ");
	
	private boolean[] bools = new boolean[alphabet.getLen()];
	private byte[] bytes = new byte[alphabet.getLen()];
	
	public void initialize()
	{
		subs.changedUpdate(null);
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		DisplayHelper.addBorder(l1, border);
		DisplayHelper.addBorder(size, border);
		table.newRow();
		table.newCol(size, 2);
		table.newRow();
		table.newCol(l1);
		table.newCol(DisplayHelper.nestBorderWide(subs, border));
		table.newRow();
	}

	public boolean error(Pointer<String> msg)
	{
		if(alphabet.getLen() != subs.getText().length()) {
			msg.set(outBounds);
			return true;
		}
		this.update();
		for(byte b : bytes)
			bools[b & 0xFF] = true;
		boolean a = true;
		for(int i = 0; i < alphabet.getLen(); i++) {
			a &= bools[i];
			bools[i] = false;
		}
		if(!a) {
			msg.set(missing);
			return true;
		}
		return false;
	}
	
	public SubstitutionKey extract()
	{
		this.update();
		return new SubstitutionKey(bytes, this.alphabet);
	}

	protected void alphabetChanged() 
	{
		final int len = alphabet.getLen();
		size.setText("Alphabet Size: " + len);
		if(len > bools.length) {
			bools = new boolean[len];
			bytes = new byte[len];
		}
	}
	
	private void update()
	{
		if(subs.hasChanged()) {
			SubstitutionKey.fromChars(alphabet, subs.getText(), bytes);
			subs.reset();
		}
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
