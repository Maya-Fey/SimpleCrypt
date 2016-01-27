import claire.simplecrypt.ciphers.feedback.AffineFeedbackCipher;
import claire.simplecrypt.ciphers.feedback.AffineFeedbackKey;
import claire.simplecrypt.coders.IgnoreCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.SimpleCryptFrame;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.test.Test;
import claire.util.crypto.rng.primitive.FastXorShift;
import claire.util.standards.IRandom;

public final class TestCrypt {

	//If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter
	public static void main(String[] args) throws Exception
	{
		Test.runTests();
		IRandom rng = new FastXorShift(2312313);
		AffineFeedbackKey key = AffineFeedbackKey.random(Alphabet.SIMPLELAB, 8, rng);
		ICipher<?, ?> cipher = new AffineFeedbackCipher(key);
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
		SimpleCryptFrame disp = new SimpleCryptFrame();
		disp.start();
	}

}
