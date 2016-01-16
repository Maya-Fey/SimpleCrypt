package claire.simplecrypt.display;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.Border;

import claire.simplecrypt.ciphers.CipherRegistry;
import claire.simplecrypt.ciphers.UKey;
import claire.simplecrypt.coders.IgnoreCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TablePane;
import claire.util.display.display.BasicDisplay;
import claire.util.display.message.ErrorMessage;
import claire.util.display.message.InformationCollectionMessage;

public class SimpleCryptFrame 
	   extends BasicDisplay
	   implements ActionListener {

	private static final long serialVersionUID = -7925874728569660321L;
	
	private final JTextArea plain = new JTextArea();
	private final JTextArea cipher = new JTextArea();
	private final JButton enc;
	private final JButton dec;
	
	private IgnoreCoder coder;
	
	private ICipher<?> cip;
	private ISecret<?> key;
	private int cID = -1;
	
	private boolean allow;
	
	private CipherChoicePanel cpanel;

	public SimpleCryptFrame()
	{
		super("SimpleCrypt");
		DisplayHelper.center(this);
		JMenu cbar = this.addMenu("Cipher");
		JMenuItem sc = new JMenuItem("Load Cipher");
		sc.setActionCommand("2");
		sc.addActionListener(this);
		cbar.add(sc);
		JMenu kbar = this.addMenu("Key");
		JMenuItem nk = new JMenuItem("New Key");
		nk.setActionCommand("3");
		nk.addActionListener(this);
		kbar.add(nk);
		plain.setRows(3);
		cipher.setRows(3);
		plain.setLineWrap(true);
		cipher.setLineWrap(true);
		JScrollPane p = DisplayHelper.getScrollPane(plain, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		JScrollPane c = DisplayHelper.getScrollPane(cipher, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		enc = new JButton("Encipher");
		dec = new JButton("Decipher");
		enc.setActionCommand("0");
		dec.setActionCommand("1");
		enc.addActionListener(this);
		dec.addActionListener(this);
		Border b = DisplayHelper.uniformBorder(5);
		DisplayHelper.addBorder(p, b);
		DisplayHelper.addBorder(c, b);
		Component e = DisplayHelper.nestBorderWide(enc, b);
		Component d = DisplayHelper.nestBorderWide(dec, b);
		TablePane pane = new TablePane(GridBagConstraints.BOTH);
		pane.newRow(1.0D);
		pane.newCol(p, 1.0D);
		pane.newCol(e, 0.75D);
		pane.newRow(1.0D);
		pane.newCol(c, 1.0D);
		pane.newCol(d, 0.75D);
		this.add(pane);
		this.disallow();
	}
	
	private void allow()
	{
		if(!allow)
		{
			plain.setEnabled(true);
			cipher.setEnabled(true);
			enc.setEnabled(true);
			dec.setEnabled(true);
			allow = true;
		}
	}
	
	private void disallow()
	{
		if(allow)
		{
			plain.setEnabled(false);
			cipher.setEnabled(false);
			enc.setEnabled(false);
			dec.setEnabled(false);
			allow = false;
		}
	}

	
	public void actionPerformed(ActionEvent arg0)
	{
		switch(arg0.getActionCommand())
		{
			case "0":
				char[] chars = plain.getText().toCharArray();
				coder.encode(chars);
				cipher.setText(new String(chars));
				break;
			case "1":
				chars = cipher.getText().toCharArray();
				coder.decode(chars);
				plain.setText(new String(chars));
				break;
			case "2":
				if(cpanel == null) {
					cpanel = new CipherChoicePanel();
					cpanel.initialize();
				}
				InformationCollectionMessage m = new InformationCollectionMessage(this.getOwner(), cpanel, "Select New Cipher", true);
				DisplayHelper.center(m);
				m.start();
				if(m.isOk()) {
					this.setCipher(cpanel.getCipherID());
				}
				break;
			case "3":
				if(cID == -1) {
					ErrorMessage e = new ErrorMessage(this.getOwner(), "No cipher selected! Use Cipher->Select Cipher to select a cipher.");
					DisplayHelper.center(e);
					e.start();
				} else {
					KeyCreatorPanel<?> p = null;
					try {
						p = CipherRegistry.getPanel(cID);
					} catch (Exception e) {
						ErrorMessage m2 = new ErrorMessage(this.getOwner(), "Error Encountered: " + e.getMessage() );
						DisplayHelper.center(m2);
						m2.start();
						e.printStackTrace();
						this.dispose();
					} 
					p.initialize();
					m = new InformationCollectionMessage(this.getOwner(), p, "Select New Cipher", true);
					DisplayHelper.center(m);
					m.start();
					if(m.isOk()) {
						ISecret<?> k = p.extract();
						try {
							this.cip = CipherRegistry.getCipher(k, cID);
						} catch (Exception e) {
							ErrorMessage m2 = new ErrorMessage(this.getOwner(), "Error Encountered: " + e.getMessage() );
							DisplayHelper.center(m2);
							m2.start();
							e.printStackTrace();
							this.dispose();
						}
						this.key = k;
						if(this.coder == null)
							coder = new IgnoreCoder(cip, 1000);
						else
							coder.setCipher(cip);
						this.allow();
					}
				}
				break;
		}
	}

	public void setCipher(int ID)
	{
		this.cID = ID;
		this.disallow();
	}
	
	public void setKey(UKey key)
	{
		this.cID = key.getID();
		this.key = key.getKey();
		try {
			this.cip = CipherRegistry.getCipher(this.key, this.cID);
		} catch (Exception e) {
			ErrorMessage m = new ErrorMessage(this.getOwner(), "Error Encountered: " + e.getMessage() );
			DisplayHelper.center(m);
			m.start();
			e.printStackTrace();
			this.dispose();
		} 
		if(this.coder == null)
			coder = new IgnoreCoder(cip, 1000);
		else
			coder.setCipher(cip);
		this.allow();
	}

}