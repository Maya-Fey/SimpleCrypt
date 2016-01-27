package claire.simplecrypt.test;

import claire.simplecrypt.ciphers.autokey.AutoKeyCipher;
import claire.simplecrypt.ciphers.autokey.AutoKeyKey;
import claire.simplecrypt.ciphers.ceasar.CeasarCipher;
import claire.simplecrypt.ciphers.ceasar.CeasarKey;
import claire.simplecrypt.ciphers.ceasar.MultiCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;
import claire.simplecrypt.ciphers.feedback.AffineFeedbackCipher;
import claire.simplecrypt.ciphers.feedback.AffineFeedbackKey;
import claire.simplecrypt.ciphers.feedback.IteratorFeedbackCipher;
import claire.simplecrypt.ciphers.feedback.IteratorFeedbackKey;
import claire.simplecrypt.ciphers.iterative.IterativeCipher;
import claire.simplecrypt.ciphers.iterative.IteratorCipher;
import claire.simplecrypt.ciphers.iterative.IteratorKey;
import claire.simplecrypt.ciphers.iterative.MultiIterative;
import claire.simplecrypt.ciphers.iterative.MultiIterator;
import claire.simplecrypt.ciphers.iterative.MultiIteratorKey;
import claire.simplecrypt.ciphers.mathematical.AffineCipher;
import claire.simplecrypt.ciphers.mathematical.AffineKey;
import claire.simplecrypt.ciphers.mathematical.MultiAffine;
import claire.simplecrypt.ciphers.mathematical.MultiAffineKey;
import claire.simplecrypt.ciphers.substitution.MultiSubstitution;
import claire.simplecrypt.ciphers.substitution.MultiSubstitutionKey;
import claire.simplecrypt.ciphers.substitution.SubstitutionCipher;
import claire.simplecrypt.ciphers.substitution.SubstitutionKey;
import claire.simplecrypt.coders.IgnoreCoder;
import claire.simplecrypt.coders.SimpleCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.IState;
import claire.util.crypto.rng.primitive.JRandom;
import claire.util.logging.Log;
import claire.util.standards.IRandom;

public final class Test {
	
	static final ICipher<?, ?> scipher = new AutoKeyCipher(new AutoKeyKey(Alphabet.SIMPLELAB, "KILT"));
	
	static final IRandom rng = new JRandom();
	
	static final ICipher<?, ?>[] ciphers = new ICipher<?, ?>[]
		{
			new CeasarCipher(CeasarKey.random(Alphabet.ADVANCED, rng)),
			new MultiCeasar(MultiCeasarKey.random(Alphabet.ADVANCED, 8, rng)),
			new SubstitutionCipher(SubstitutionKey.random(Alphabet.ADVANCED, rng)),
			new MultiSubstitution(MultiSubstitutionKey.random(Alphabet.ADVANCED, 8, rng)),
			new AffineCipher(AffineKey.random(Alphabet.ADVANCED, rng)),
			new MultiAffine(MultiAffineKey.random(Alphabet.ADVANCED, 8, rng)),
			new IterativeCipher(IteratorKey.random(Alphabet.ADVANCED, rng)),
			new IteratorCipher(IteratorKey.random(Alphabet.ADVANCED, rng)),
			new MultiIterative(MultiIteratorKey.random(Alphabet.ADVANCED, 8, rng)),
			new MultiIterator(MultiIteratorKey.random(Alphabet.ADVANCED, 8, rng)),
			new AutoKeyCipher(AutoKeyKey.random(Alphabet.ADVANCED, 8, rng)),
			new IteratorFeedbackCipher(IteratorFeedbackKey.random(Alphabet.ADVANCED, 8, rng)),
			new AffineFeedbackCipher(AffineFeedbackKey.random(Alphabet.ADVANCED, 8, rng))
		};
	
	static final ICharCoder[] coders = new ICharCoder[]
		{
			new SimpleCoder(scipher, 1000),
			new IgnoreCoder(scipher, 1000)
		};
	
	static final ISecret<?>[] keys = new ISecret<?>[ciphers.length];
	
	static IState<?>[] states;
	
	static 
	{
		int j = 0;
		for(int i = 0; i < ciphers.length; i++) {
			keys[i] = ciphers[i].getKey();
			if(ciphers[i].hasState())
				j++;
		}
		states = new IState<?>[j];
		for(int i = 0; i < ciphers.length; i++) {
			if(ciphers[i].hasState())
				states[--j] = ciphers[i].getState();
		}
	}
	
	public static final void runTests()
	{
		int fails = 0;
		Log.info.println("Running tests...");
		fails += PersistTest.runTest();
		fails += CipherTest.runTest();
		fails += CoderTest.runTest();
		if(fails > 0)
			Log.crit.println(fails + " regressions detected!");
		else
			Log.info.println("Success! No regressions caught by tests.");
	}

}
