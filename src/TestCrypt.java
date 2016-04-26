import claire.simplecrypt.ciphers.feistel.FeistelKey;
import claire.simplecrypt.ciphers.feistel.IterativeFeistel;
import claire.simplecrypt.coders.IgnoreCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.SimpleCryptFrame;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.test.Test;
import claire.util.crypto.rng.primitive.FastXorShift;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.crypto.IRandom;

public final class TestCrypt {

	//If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter
	public static void main(String[] args) throws Exception
	{
		Test.runTests();
		IRandom<?> rng = new FastXorShift(2312313);
		FeistelKey key = new FeistelKey(Alphabet.ADVANCED, Alphabet.ADVANCED.convertTo(new String("Carter").toCharArray(), 0, 3));
		ICipher<?, ?> cipher = new IterativeFeistel(key);
		ICharCoder coder = new IgnoreCoder(cipher, 1000);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		final int orig = text.length;
		text = ArrayUtil.upsize(text, coder.ciphertextSize(text) - text.length);
		System.out.println(text);
		coder.encode(text, 0, orig);
		System.out.println(text);
		coder.decode(text);
		System.out.println(text);
		System.out.println();
		cipher.reset();
		text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toCharArray();
		text = ArrayUtil.upsize(text, coder.ciphertextSize(text) - text.length);
		System.out.println(text);
		coder.encode(text, 0, orig);
		System.out.println(text);
		coder.decode(text);
		System.out.println(text);
		SimpleCryptFrame disp = new SimpleCryptFrame();
		disp.start();
	}

}
