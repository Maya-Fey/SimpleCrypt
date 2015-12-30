import claire.simplecrypt.ciphers.substitution.MultiIteratorSubstitution;
import claire.simplecrypt.ciphers.substitution.MultiIteratorSubstitutionKey;
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
		MultiIteratorSubstitutionKey key = MultiIteratorSubstitutionKey.random(Alphabet.ADVANCED, 2, rng);
		ICipher<?> cipher = new MultiIteratorSubstitution(key);
		char[] text = "If P = NP, then the entire universe is highly likely to explode in 12 minutes - Samantha Carter".toCharArray();
		System.out.println(text);
		cipher.encipher(text);
		System.out.println(text);
		cipher.decipher(text);
		System.out.println(text);
	}

}
