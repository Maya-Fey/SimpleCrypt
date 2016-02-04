package claire.simplecrypt.display.creators;

import javax.swing.JLabel;
import javax.swing.JTextField;

import claire.simplecrypt.ciphers.fraction.PolybiusKey;
import claire.util.display.DisplayHelper;
import claire.util.encoding.EncodingUtil;
import claire.util.memory.util.Pointer;

public class PolybiusKeyCreator 
	   extends KeyCreatorPanel<PolybiusKey> {

	private static final long serialVersionUID = -5831483180721711993L;
	
	private final JTextField fieldx = new JTextField(4);
	private final JTextField fieldy = new JTextField(4);
	private final JLabel size = new JLabel();
	private final JLabel l1 = new JLabel();
	private final JLabel l2 = new JLabel();
	
	private int x, y;
	
	public void initialize()
	{
		this.alphabetChanged();
		DisplayHelper.addBorder(l1, border);
		DisplayHelper.addBorder(l2, border);
		DisplayHelper.addBorder(size, border);
		table.newRow();
		table.newCol(size, 2);
		table.newRow();
		table.newCol(l1);
		table.newCol(DisplayHelper.nestBorderWide(fieldx, border));
		table.newRow();
		table.newCol(l2);
		table.newCol(DisplayHelper.nestBorderWide(fieldy, border));
	}

	public boolean error(Pointer<String> msg)
	{
		final String xt = fieldx.getText();
		final String yt = fieldy.getText();
		if(xt.length() != x) {
			msg.set("Error, X-Axis key has an incorrect length");
			return true;
		}
		if(yt.length() != y) {
			msg.set("Error, Y-Axis key has an incorrect length");
			return true;
		}
		if(!alphabet.containsOnly(xt)) {
			msg.set("Error, X-Axis contains chars not in the alphabet");
			return true;
		}
		if(!alphabet.containsOnly(yt)) {
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
	
	public PolybiusKey extract()
	{
		final char[] xt = fieldx.getText().toCharArray();
		final char[] yt = fieldy.getText().toCharArray();
		return new PolybiusKey(alphabet, alphabet.convertTo(xt, 0, xt.length), alphabet.convertTo(yt, 0, yt.length));
	}

	protected void alphabetChanged() 
	{
		size.setText("Alphabet Size: " + this.getAlphabet().getLen());
		l1.setText("Enter X axis key (" + (x = PolybiusKey.getRow(alphabet.getID())) + " chars)");
		l2.setText("Enter Y axis key (" + (y = PolybiusKey.getCol(alphabet.getID())) + " chars)");
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
