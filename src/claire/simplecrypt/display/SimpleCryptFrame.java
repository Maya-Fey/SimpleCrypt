package claire.simplecrypt.display;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.Border;

import claire.simplecrypt.ciphers.CipherRegistry;
import claire.simplecrypt.ciphers.UKey;
import claire.simplecrypt.ciphers.UState;
import claire.simplecrypt.coders.IgnoreCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.creators.KeyCreatorPanel;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.IState;
import claire.util.display.DisplayHelper;
import claire.util.display.component.TablePane;
import claire.util.display.display.BasicDisplay;
import claire.util.display.message.ConfirmMessage;
import claire.util.display.message.ErrorMessage;
import claire.util.display.message.FileSelectionMessage;
import claire.util.display.message.InformationCollectionMessage;

public class SimpleCryptFrame 
	   extends BasicDisplay
	   implements ActionListener {

	private static final long serialVersionUID = -7925874728569660321L;
	
	private final JTextArea plain = new JTextArea();
	private final JTextArea cipher = new JTextArea();
	private final JButton enc;
	private final JButton dec;
	private final JMenu kbar;
	private final JMenu sbar;
	private final JMenuItem sk;
	private final JMenuItem ls;

	private IgnoreCoder coder;
	
	private ICipher<?, IState<?>> cip;
	private ISecret<?> key;
	private IState<?> state;
	private int cID = -1;
	
	private boolean allow = true;
	
	private CipherChoicePanel cpanel;
	private AlphabetChoicePanel apanel;

	public SimpleCryptFrame()
	{
		super("SimpleCrypt");
		DisplayHelper.center(this);
		JMenu cbar = this.addMenu("Cipher");
		JMenuItem sc = new JMenuItem("New");
		sc.setActionCommand("2");
		sc.addActionListener(this);
		cbar.add(sc);
		JMenuItem lc = new JMenuItem("Load from Key");
		lc.setActionCommand("8");
		lc.addActionListener(this);
		cbar.add(lc);
		JMenu kbar = this.kbar = this.addMenu("Key");
		JMenuItem nk = new JMenuItem("New");
		nk.setActionCommand("3");
		nk.addActionListener(this);
		kbar.add(nk);
		JMenuItem rk = new JMenuItem("Random");
		rk.setActionCommand("5");
		rk.addActionListener(this);
		kbar.add(rk);
		JMenuItem sk = this.sk = new JMenuItem("Save");
		sk.setActionCommand("6");
		sk.addActionListener(this);
		kbar.add(sk);
		JMenuItem ok = new JMenuItem("Open");
		ok.setActionCommand("7");
		ok.addActionListener(this);
		kbar.add(ok);
		JMenu sbar = this.sbar = this.addMenu("State");
		JMenuItem rs = new JMenuItem("Reset");
		rs.setActionCommand("4");
		rs.addActionListener(this);
		sbar.add(rs);
		JMenuItem ss = new JMenuItem("Save");
		ss.setActionCommand("9");
		ss.addActionListener(this);
		sbar.add(ss);
		JMenuItem ls = this.ls = new JMenuItem("Load");
		ls.setActionCommand("10");
		ls.addActionListener(this);
		sbar.add(ls);
		JMenuItem sfs = new JMenuItem("Save to File");
		sfs.setActionCommand("11");
		sfs.addActionListener(this);
		sbar.add(sfs);
		JMenuItem lfs = new JMenuItem("Load from File");
		lfs.setActionCommand("12");
		lfs.addActionListener(this);
		sbar.add(lfs);
		kbar.setEnabled(false);
		plain.setRows(3);
		cipher.setRows(3);
		plain.setLineWrap(true);
		cipher.setLineWrap(true);
		JScrollPane p = new JScrollPane(plain, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		JScrollPane c = new JScrollPane(cipher, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
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
			if(cip.hasState())
				sbar.setEnabled(true);
			sk.setEnabled(true);
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
			sbar.setEnabled(false);
			sk.setEnabled(false);
			ls.setEnabled(false);
			allow = false;
		}
	}

	/**
	 * TODO: A bit of spaghetti here, use a fork to clear it out.
	 */
	public void actionPerformed(ActionEvent arg0)
	{
		switch(arg0.getActionCommand())
		{
			case "0":
				char[] chars = plain.getText().toCharArray();
				int nlen = coder.ciphertextSize(chars);
				if(nlen != chars.length) {
					char[] nc = new char[nlen];
					coder.encode(chars, 0, nc, 0, chars.length);
					cipher.setText(new String(nc));
				} else {
					coder.encode(chars);
					cipher.setText(new String(chars));
				}
				break;
				
				
			case "1":
				chars = cipher.getText().toCharArray();
				nlen = coder.ciphertextSize(chars);
				if(nlen != chars.length) {
					char[] nc = new char[nlen];
					coder.decode(chars, 0, nc, 0, chars.length);
					plain.setText(new String(nc));
				} else {
					coder.decode(chars);
					plain.setText(new String(chars));
				}
				break;
				
				
			case "2":
				if(cpanel == null) {
					cpanel = new CipherChoicePanel();
					cpanel.initialize();
				}
				if(key != null) {
					ConfirmMessage c = new ConfirmMessage(this.getOwner(), "Are you sure?", "Changing ciphers will destroy the current k in memory, make sure to save it to file if you want to keep the key for future communication. If you wish to save the cipher state, you should do that now aswell.");
					DisplayHelper.center(c);
					c.start();
					if(!c.isOk())
						break;
				}
				InformationCollectionMessage m = new InformationCollectionMessage(this.getOwner(), cpanel, "Select New Cipher", true);
				DisplayHelper.center(m);
				m.start();
				if(m.isOk()) {
					if(cID == -1) 
						kbar.setEnabled(true);
					this.setCipher(cpanel.getCipherID());
					key = null;
				}
				break;
				
				
			case "3":
				if(cID == -1) 
					this.showError("No cipher selected! Use Cipher->Select Cipher to select a cipher.");
				else {
					if(key != null) {
						ConfirmMessage c = new ConfirmMessage(this.getOwner(), "Are you sure?", "Creating a new key will destroy the current one in memory, make sure to save it to file if you want to keep the key for future communication. If you wish to save the cipher state, you should do that now aswell.");
						DisplayHelper.center(c);
						c.start();
						if(!c.isOk())
							break;
					}
					KeyCreatorPanel<?> p = null;
					try {
						p = CipherRegistry.getPanel(cID);
					} catch (Exception e) {
						e.printStackTrace();
						this.showErrorClose("Error Encountered: " + e.getMessage());
						break;
					} 
					p.initialize();
					m = new InformationCollectionMessage(this.getOwner(), p, "Create " + CipherRegistry.getName(cID) + " Key", true);
					DisplayHelper.center(m);
					m.start();
					if(m.isOk()) 
						try {
							this.setKey(p.extract());
						} catch (Exception e) {
							e.printStackTrace();
							this.showErrorClose("Error Encountered: " + e.getMessage());
							break;
						}
				}
				break;
				
				
			case "4":
				cip.reset();
				break;
				
				
			case "5":
				if(cID == -1) {
					this.showError("No cipher selected! Use Cipher->Select Cipher to select a cipher.");
					break;
				}
				if(key != null) {
					ConfirmMessage c = new ConfirmMessage(this.getOwner(), "Are you sure?", "Creating a new key will destroy the current one in memory, make sure to save it to file if you want to keep the key for future communication. If you wish to save the cipher state, you should do that now aswell.");
					DisplayHelper.center(c);
					c.start();
					if(!c.isOk())
						break;
				}
				if(apanel == null) {
					apanel = new AlphabetChoicePanel();
					apanel.initialize();
				}
				m = new InformationCollectionMessage(this.getOwner(), apanel, "Select Alphabet for Random Key", true);
				DisplayHelper.center(m);
				m.start();
				if(m.isOk()) {
					Alphabet a = Alphabet.fromID(apanel.getAlphabetID());
					try {
						this.setKey(CipherRegistry.random(cID, a));
					} catch (Exception e) {
						e.printStackTrace();
						this.showErrorClose("Error Encountered: " + e.getMessage());
					}
				}
				break;
				
				
			case "6":
				FileSelectionMessage s = FileSelectionMessage.saveFilePane(this.getOwner(), new File("/"), "Save " + CipherRegistry.getName(cID) + " Key", true);
				DisplayHelper.center(s);
				s.start();
				if(s.isOk()) {
					File f = s.getFile();
					UKey key = new UKey(this.key, cID);
					try {
						key.export(f);
					} catch (IOException e) {
						this.showError("I/O Exception encountered while attempting to save file: " + e.getMessage());
						e.printStackTrace();
					}
				}
				break;
				
				
			case "7":
				s = FileSelectionMessage.openFilePane(this.getOwner(), new File("/"), "Open " + CipherRegistry.getName(cID) + " Key", true);
				DisplayHelper.center(s);
				s.start();
				if(s.isOk()) {
					File f = s.getFile();
					UKey key;
					
					
					try {
						key = UKey.factory.resurrect(f);
					} catch (Exception e) {
						this.showError("Exception encountered while attempting to open key: " + e.getMessage());
						e.printStackTrace();
						break;
					}
					
					
					if(key.getID() != cID) {
						this.showError("Wrong key type (" + CipherRegistry.getName(key.getID()) + " Key), expected " + CipherRegistry.getName(cID) + " Key.");
						break;
					}
					
					
					try {
						this.setKey(key.getKey());
					} catch (Exception e) {
						e.printStackTrace();
						this.showErrorClose("Error Encountered: " + e.getMessage());
					}
				}
				break;
				
				
			case "8":
				s = FileSelectionMessage.openFilePane(this.getOwner(), new File("/"), "Open Key", true);
				DisplayHelper.center(s);
				s.start();
				if(s.isOk()) {
					File f = s.getFile();
					UKey key;
					
					
					try {
						key = UKey.factory.resurrect(f);
					} catch (Exception e) {
						this.showError("Exception encountered while attempting to open key: " + e.getMessage());
						e.printStackTrace();
						break;
					}
					
					
					if(cID == -1) 
						kbar.setEnabled(true);
					cID = key.getID();
					
					try {
						this.setKey(key.getKey());
					} catch (Exception e) {
						e.printStackTrace();
						this.showErrorClose("Error Encountered: " + e.getMessage());
					}
				}
				break;
			case "9":
				if(state == null) {
					state = cip.getState();
					ls.setEnabled(true);
				} else
					cip.updateState(state);
				break;
				
			case "10":
				cip.loadState(state);
				break;
				
			case "11":
				if(state == null) {
					ConfirmMessage c = new ConfirmMessage(this.getOwner(), "Are you sure?", "There is no state in memory, this means the program will save the current state of the cipher and put the saved state in memory also. Do you wish to do this?");
					DisplayHelper.center(c);
					c.start();
					if(!c.isOk())
						break;
					state = cip.getState();
					ls.setEnabled(true);
				} 
				s = FileSelectionMessage.saveFilePane(this.getOwner(), new File("/"), "Save " + CipherRegistry.getName(cID) + " Key", true);
				DisplayHelper.center(s);
				s.start();
				if(s.isOk()) {
					File f = s.getFile();
					UState ns = new UState(state, cID);
					try {
						ns.export(f);
					} catch (IOException e) {
						this.showError("I/O Exception encountered while attempting to save file: " + e.getMessage());
						e.printStackTrace();
					}
				}
				break;
			
			case "12":
				if(state != null) 
					if(!DisplayHelper.confirm(this.getOwner(), "Question!", "There is currently a state in memory, this operation will replace that with the state you load from file, are you sure you want to do this?"))
						break;
				s = FileSelectionMessage.openFilePane(this.getOwner(), new File("/"), "Open State", true);
				DisplayHelper.center(s);
				s.start();
				if(s.isOk()) {
					File f = s.getFile();
					UState state;
					
					
					try {
						state = UState.factory.resurrect(f);
					} catch (Exception e) {
						this.showError("Exception encountered while attempting to open key: " + e.getMessage());
						e.printStackTrace();
						break;
					}
					
					if(state.getID() != cID) {
						this.showError("Wrong state type (" + CipherRegistry.getName(state.getID()) + " Key), expected " + CipherRegistry.getName(cID) + " Key.");
						break;
					}
					
					try {
						this.state = state.getState();
						cip.loadState(this.state);
						ls.setEnabled(true);
					} catch (Exception e) {
						e.printStackTrace();
						this.showErrorClose("Error Encountered: " + e.getMessage() + "\n\nThis could be due to the state belonging to another key.");
					}
				}
				break;
		}
	}

	protected void setKey(ISecret<?> key) throws Exception
	{
		try {
			this.cip = CipherRegistry.getCipher(key, cID);
		} catch (Exception e) {
			e.printStackTrace();
			this.showErrorClose("Error Encountered: " + e.getMessage());
		}
		this.key = key;
		ls.setEnabled(false);
		state = null;
		
		if(this.coder == null)
			coder = new IgnoreCoder(cip, 1000);
		else
			coder.setCipher(cip);
		this.allow();
	}
	
	public void showError(String message)
	{
		ErrorMessage m2 = new ErrorMessage(this.getOwner(), message);
		DisplayHelper.center(m2);
		m2.start();
	}
	
	public void showErrorClose(String message)
	{
		ErrorMessage m2 = new ErrorMessage(this.getOwner(), message);
		DisplayHelper.center(m2);
		m2.start();
		this.dispose();
		this.setVisible(false);
	}

	public void setCipher(int ID)
	{
		this.cID = ID;
		this.disallow();
	}

}
