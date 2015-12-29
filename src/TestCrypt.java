import claire.simplecrypt.ciphers.ceasar.MultiIteratorCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiIteratorCeasarKey;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.util.crypto.rng.primitive.FastXorShift;
import claire.util.standards.IRandom;

public final class TestCrypt {

	//If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter
	public static void main(String[] args)
	{
		IRandom rng = new FastXorShift(2312312);
		MultiIteratorCeasarKey key = MultiIteratorCeasarKey.random(Alphabet.ADVANCED, 4, rng);
		ICipher<?> cipher = new MultiIteratorCeasar(key);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		System.out.println(text);
		cipher.encipher(text);
		System.out.println(text);
		cipher.decipher(text);
		System.out.println(text);
	}

}
