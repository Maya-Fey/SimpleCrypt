import claire.simplecrypt.ciphers.iterative.MultiIterator;
import claire.simplecrypt.ciphers.iterative.MultiIteratorKey;
import claire.simplecrypt.coders.SimpleCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.test.Test;
import claire.util.crypto.rng.primitive.FastXorShift;
import claire.util.standards.IRandom;

public final class TestCrypt {

	//If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter
	public static void main(String[] args)
	{
		Test.runTests();
		IRandom rng = new FastXorShift(2312313);
		MultiIteratorKey key = MultiIteratorKey.random(Alphabet.ADVANCED, 8, rng);
		ICipher<?> cipher = new MultiIterator(key);
		ICharCoder coder = new SimpleCoder(cipher, 1000);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		System.out.println(text);
		coder.encode(text);
		System.out.println(text);
		coder.decode(text);
		System.out.println(text);
		System.out.println();
		text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toCharArray();
		System.out.println(text);
		coder.encode(text);
		System.out.println(text);
		coder.decode(text);
		System.out.println(text);
	}

}
