package claire.simplecrypt.test;

import claire.simplecrypt.ciphers.ceasar.CeasarCipher;
import claire.simplecrypt.ciphers.ceasar.CeasarKey;
import claire.simplecrypt.ciphers.ceasar.MultiCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;
import claire.simplecrypt.ciphers.iterative.IterativeCipher;
import claire.simplecrypt.ciphers.iterative.IteratorCipher;
import claire.simplecrypt.ciphers.iterative.IteratorKey;
import claire.simplecrypt.ciphers.mathematical.AffineCipher;
import claire.simplecrypt.ciphers.mathematical.AffineKey;
import claire.simplecrypt.ciphers.mathematical.MultiAffine;
import claire.simplecrypt.ciphers.mathematical.MultiAffineKey;
import claire.simplecrypt.ciphers.substitution.MultiSubstitution;
import claire.simplecrypt.ciphers.substitution.MultiSubstitutionKey;
import claire.simplecrypt.ciphers.substitution.SubstitutionCipher;
import claire.simplecrypt.ciphers.substitution.SubstitutionKey;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.util.crypto.rng.primitive.JRandom;
import claire.util.logging.Log;
import claire.util.standards.IRandom;

public final class Test {
	
	static final IRandom rng = new JRandom();
	
	static ICipher<?>[] ciphers = new ICipher<?>[]
		{
			new CeasarCipher(CeasarKey.random(Alphabet.ADVANCED, rng)),
			new MultiCeasar(MultiCeasarKey.random(Alphabet.ADVANCED, 8, rng)),
			new SubstitutionCipher(SubstitutionKey.random(Alphabet.ADVANCED, rng)),
			new MultiSubstitution(MultiSubstitutionKey.random(Alphabet.ADVANCED, 8, rng)),
			new AffineCipher(AffineKey.random(Alphabet.ADVANCED, rng)),
			new MultiAffine(MultiAffineKey.random(Alphabet.ADVANCED, 8, rng)),
			new IterativeCipher(IteratorKey.random(Alphabet.ADVANCED, rng)),
			new IteratorCipher(IteratorKey.random(Alphabet.ADVANCED, rng))
		};
	
	static ISecret<?>[] keys = new ISecret<?>[ciphers.length];
	
	static 
	{
		for(int i = 0; i < ciphers.length; i++)
			keys[i] = ciphers[i].getKey();
	}
	
	public static final void runTests()
	{
		int fails = 0;
		Log.info.println("Running tests...");
		fails += PersistTest.runTest();
		fails += CipherTest.runTest();
		if(fails > 0)
			Log.crit.println(fails + " regressions detected!");
		else
			Log.info.println("Success! No regressions caught by tests.");
	}

}
