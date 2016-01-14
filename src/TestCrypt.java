import javax.swing.JLabel;

import claire.simplecrypt.ciphers.autokey.AutoKeyCipher;
import claire.simplecrypt.ciphers.autokey.AutoKeyKey;
import claire.simplecrypt.coders.IgnoreCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.CeasarKeyCreator;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.test.Test;
import claire.util.crypto.rng.primitive.FastXorShift;
import claire.util.display.DisplayHelper;
import claire.util.display.display.SimpleDisplay;
import claire.util.display.message.InformationCollectionMessage;
import claire.util.display.message.InformationCollectionPanel;
import claire.util.standards.IRandom;

public final class TestCrypt {

	//If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter
	public static void main(String[] args) throws Exception
	{
		Test.runTests();
		IRandom rng = new FastXorShift(2312313);
		AutoKeyKey key = AutoKeyKey.random(Alphabet.SIMPLELAB, 8, rng);
		ICipher<?> cipher = new AutoKeyCipher(key);
		ICharCoder coder = new IgnoreCoder(cipher, 1000);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		System.out.println(text);
		coder.encode(text);
		System.out.println(text);
		coder.decode(text);
		System.out.println(text);
		System.out.println();
		cipher.reset();
		text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toCharArray();
		System.out.println(text);
		coder.encode(text);
		System.out.println(text);
		coder.decode(text);
		System.out.println(text);
		InformationCollectionPanel panel = new CeasarKeyCreator();
		JLabel label = new JLabel("Kek");
		SimpleDisplay frame = new SimpleDisplay("Lol");
		frame.add(label);
		InformationCollectionMessage m = new InformationCollectionMessage(frame.getOwner(), panel, "Spies", true);
		frame.setSize(300, 200);
		DisplayHelper.center(frame);
		frame.setVisible(true);
		panel.initialize();
		DisplayHelper.center(m);
		m.start();
		
		
	}

}
