package claire.simplecrypt.test;

import claire.simplecrypt.ciphers.ceasar.CeasarCipher;
import claire.simplecrypt.ciphers.ceasar.CeasarKey;
import claire.simplecrypt.ciphers.ceasar.IterativeCeasar;
import claire.simplecrypt.ciphers.ceasar.IteratorCeasar;
import claire.simplecrypt.ciphers.ceasar.IteratorCeasarKey;
import claire.simplecrypt.ciphers.ceasar.MultiCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;
import claire.simplecrypt.ciphers.ceasar.MultiIterativeCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiIteratorCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiIteratorCeasarKey;
import claire.simplecrypt.ciphers.mathematical.AffineCipher;
import claire.simplecrypt.ciphers.mathematical.AffineKey;
import claire.simplecrypt.ciphers.substitution.IterativeSubstitution;
import claire.simplecrypt.ciphers.substitution.IteratorSubstitution;
import claire.simplecrypt.ciphers.substitution.IteratorSubstitutionKey;
import claire.simplecrypt.ciphers.substitution.MultiIterativeSubstitution;
import claire.simplecrypt.ciphers.substitution.MultiIteratorSubstitution;
import claire.simplecrypt.ciphers.substitution.MultiIteratorSubstitutionKey;
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
			new IterativeCeasar(CeasarKey.random(Alphabet.ADVANCED, rng)),
			new IteratorCeasar(IteratorCeasarKey.random(Alphabet.ADVANCED, rng)),
			new MultiCeasar(MultiCeasarKey.random(Alphabet.ADVANCED, 8, rng)),
			new MultiIterativeCeasar(MultiCeasarKey.random(Alphabet.ADVANCED, 8, rng)),
			new MultiIteratorCeasar(MultiIteratorCeasarKey.random(Alphabet.ADVANCED, 8, rng)),
			new SubstitutionCipher(SubstitutionKey.random(Alphabet.ADVANCED, rng)),
			new IterativeSubstitution(SubstitutionKey.random(Alphabet.ADVANCED, rng)),
			new IteratorSubstitution(IteratorSubstitutionKey.random(Alphabet.ADVANCED, rng)),
			new MultiSubstitution(MultiSubstitutionKey.random(Alphabet.ADVANCED, 8, rng)),
			new MultiIterativeSubstitution(MultiSubstitutionKey.random(Alphabet.ADVANCED, 8, rng)),
			new MultiIteratorSubstitution(MultiIteratorSubstitutionKey.random(Alphabet.ADVANCED, 8, rng)),
			new AffineCipher(AffineKey.random(Alphabet.ADVANCED, rng))
		
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
