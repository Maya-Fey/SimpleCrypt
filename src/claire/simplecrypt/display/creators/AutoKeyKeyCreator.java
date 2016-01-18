package claire.simplecrypt.display.creators;

import javax.swing.JLabel;
import javax.swing.JTextField;

import claire.simplecrypt.ciphers.autokey.AutoKeyKey;
import claire.util.display.DisplayHelper;
import claire.util.memory.util.Pointer;

public class AutoKeyKeyCreator 
	   extends KeyCreatorPanel<AutoKeyKey> {

	private static final long serialVersionUID = 2052224542214347255L;
	
	private static final String none = "No key entered!";
	private static final String oob = "Key contains characters not in selected alphabet";
	
	private final JTextField key = new JTextField();
	private final JLabel l1 = new JLabel("Enter starting key: ");

	public AutoKeyKey extract()
	{
		return new AutoKeyKey(alphabet, key.getText());
	}

	public void initialize()
	{
		DisplayHelper.addBorder(l1, border);
		table.newRow();
		table.newCol(l1);
		table.newCol(DisplayHelper.nestBorderWide(key, border));
	}
	
	protected void alphabetChanged() {}

	public boolean error(Pointer<String> msg)
	{
		String text = key.getText();
		int len = text.length();
		if(len == 0) {
			msg.set(none);
			return true;
		}
		while(--len >= 0)
			if(!alphabet.contains(text.charAt(len))) {
				msg.set(oob);
				return true;
			}
		return false;
	}
	
	public int requestedHeight()
	{
		return 225;
	}
	
	public int requestedWidth()
	{
		return 400;
	}

}
