import claire.simplecrypt.ciphers.ceasar.MultiCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.util.crypto.rng.primitive.FastXorShift;
import claire.util.crypto.rng.primitive.JRandom;
import claire.util.standards.IRandom;

public final class TestCrypt {

	//If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter
	public static void main(String[] args)
	{
		IRandom rng = new FastXorShift(2312312);
		MultiCeasarKey key = MultiCeasarKey.random(Alphabet.ADVANCED, 16, new GoodRNG(new JRandom(42)));
		ICipher<?> cipher = new MultiCeasar(key);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		System.out.println(text);
		cipher.encipher(text);
		System.out.println(text);
		cipher.decipher(text);
		System.out.println(text);
	}

}
