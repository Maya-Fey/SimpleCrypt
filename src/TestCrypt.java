import claire.simplecrypt.ciphers.mathematical.IteratorAffine;
import claire.simplecrypt.ciphers.mathematical.IteratorAffineKey;
import claire.simplecrypt.data.Alphabet;
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
		IteratorAffineKey key = IteratorAffineKey.random(Alphabet.ADVANCED, rng);
		ICipher<?> cipher = new IteratorAffine(key);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		System.out.println(text);
		cipher.encipher(text);
		System.out.println(text);
		cipher.decipher(text);
		System.out.println(text);
	}

}
