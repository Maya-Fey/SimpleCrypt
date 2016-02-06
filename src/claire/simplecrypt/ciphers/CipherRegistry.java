package claire.simplecrypt.ciphers;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

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
import claire.simplecrypt.ciphers.fraction.MultiPolybius;
import claire.simplecrypt.ciphers.fraction.MultiPolybiusKey;
import claire.simplecrypt.ciphers.fraction.PolybiusCipher;
import claire.simplecrypt.ciphers.fraction.PolybiusKey;
import claire.simplecrypt.ciphers.iterative.IterativeCipher;
import claire.simplecrypt.ciphers.iterative.IteratorCipher;
import claire.simplecrypt.ciphers.iterative.IteratorKey;
import claire.simplecrypt.ciphers.iterative.IteratorState;
import claire.simplecrypt.ciphers.iterative.MultiIterative;
import claire.simplecrypt.ciphers.iterative.MultiIterator;
import claire.simplecrypt.ciphers.iterative.MultiIteratorKey;
import claire.simplecrypt.ciphers.iterative.MultiIteratorState;
import claire.simplecrypt.ciphers.mathematical.AffineCipher;
import claire.simplecrypt.ciphers.mathematical.AffineKey;
import claire.simplecrypt.ciphers.mathematical.MultiAffine;
import claire.simplecrypt.ciphers.mathematical.MultiAffineKey;
import claire.simplecrypt.ciphers.substitution.MultiSubstitution;
import claire.simplecrypt.ciphers.substitution.MultiSubstitutionKey;
import claire.simplecrypt.ciphers.substitution.SubstitutionCipher;
import claire.simplecrypt.ciphers.substitution.SubstitutionKey;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.creators.AffineFeedbackKeyCreator;
import claire.simplecrypt.display.creators.AffineKeyCreator;
import claire.simplecrypt.display.creators.AutoKeyKeyCreator;
import claire.simplecrypt.display.creators.CeasarKeyCreator;
import claire.simplecrypt.display.creators.IterativeKeyCreator;
import claire.simplecrypt.display.creators.IteratorFeedbackKeyCreator;
import claire.simplecrypt.display.creators.IteratorKeyCreator;
import claire.simplecrypt.display.creators.KeyCreatorPanel;
import claire.simplecrypt.display.creators.MultiAffineKeyCreator;
import claire.simplecrypt.display.creators.MultiCeasarKeyCreator;
import claire.simplecrypt.display.creators.MultiIterativeKeyCreator;
import claire.simplecrypt.display.creators.MultiIteratorKeyCreator;
import claire.simplecrypt.display.creators.MultiPolybiusKeyCreator;
import claire.simplecrypt.display.creators.MultiSubstitutionKeyCreator;
import claire.simplecrypt.display.creators.PolybiusKeyCreator;
import claire.simplecrypt.display.creators.SubstitutionKeyCreator;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.IState;
import claire.util.io.Factory;
import claire.util.logging.Log;
import claire.util.memory.array.Registry;

@SuppressWarnings("unchecked")
public final class CipherRegistry {
	
	private static final int SIZE = 15;
	
	private static final Class<?>[] args0 = new Class<?>[] 
		{
			ISecret.class
		};
	
	private static final Class<?>[] args1 = new Class<?>[]
		{
		
		};
	
	/*
	 * Why? I cannot be assed. Every bit of code has its ugly spot where it
	 * actually does work. Some try to act goodie-two-shoes by hiding it behind
	 * 5 libraries (which do exactly what they didn't want to), sacrificing 
	 * performance tenfold, having a method for every line of code, or a combination. 
	 * This class is where the nitty gritty shit  happens, but it'll get the job
	 * done and it's straightforward to add exactly what you're supposed to add: 
	 * more ciphers.
	 */
	private static final CipherFactory<?, ? extends ISecret<?>, ? extends KeyCreatorPanel<?>, IState<?>>[] factories = (CipherFactory<?, ? extends ISecret<?>, ? extends KeyCreatorPanel<?>, IState<?>>[]) new CipherFactory<?, ?, ?, ?>[SIZE];
	private static final Registry<CipherFactory<?, ? extends ISecret<?>, ? extends KeyCreatorPanel<?>, IState<?>>> reg = new Registry<CipherFactory<?, ? extends ISecret<?>, ? extends KeyCreatorPanel<?>, IState<?>>>(factories);
	
	public static final String[] names = new String[]
		{
			"Ceasar Cipher",
			"Vigenere Cipher (Multi Ceasar)",
			"Cipher AutoKey",
			"Iterative Cipher",
			"Iterator Cipher",
			"Multi Iterative Cipher",
			"Multi Iterator Cipher",
			"Affine Cipher",
			"Multi Affine Cipher",
			"Substitution Cipher",
			"Multi Substitution Cipher",
			"Iterator Feedback Cipher",
			"Affine Feedback Cipher",
			"Polybius Square Cipher",
			"Multi Polybius Cipher"
		};
	
	static {
		try {
			add(CeasarKey.class, CeasarCipher.class, CeasarKeyCreator.class.getConstructor(args1), CeasarKey.factory, null);
			add(MultiCeasarKey.class, MultiCeasar.class, MultiCeasarKeyCreator.class.getConstructor(args1), MultiCeasarKey.factory, MultiCeasar.sfactory);
			add(AutoKeyKey.class, AutoKeyCipher.class, AutoKeyKeyCreator.class.getConstructor(args1), AutoKeyKey.factory, AutoKeyCipher.sfactory);
			add(IteratorKey.class, IterativeCipher.class, IterativeKeyCreator.class.getConstructor(args1), IteratorKey.factory, IteratorState.factory);
			add(IteratorKey.class, IteratorCipher.class, IteratorKeyCreator.class.getConstructor(args1), IteratorKey.factory, IteratorState.factory);
			add(MultiIteratorKey.class, MultiIterative.class, MultiIterativeKeyCreator.class.getConstructor(args1), MultiIteratorKey.factory, MultiIteratorState.sfactory);
			add(MultiIteratorKey.class, MultiIterator.class, MultiIteratorKeyCreator.class.getConstructor(args1), MultiIteratorKey.factory, MultiIteratorState.sfactory);
			add(AffineKey.class, AffineCipher.class, AffineKeyCreator.class.getConstructor(args1), AffineKey.factory, null);
			add(MultiAffineKey.class, MultiAffine.class, MultiAffineKeyCreator.class.getConstructor(args1), MultiAffineKey.factory, MultiAffine.sfactory);
			add(SubstitutionKey.class, SubstitutionCipher.class, SubstitutionKeyCreator.class.getConstructor(args1), SubstitutionKey.factory, null);
			add(MultiSubstitutionKey.class, MultiSubstitution.class, MultiSubstitutionKeyCreator.class.getConstructor(args1), MultiSubstitutionKey.factory, MultiSubstitution.sfactory);
			add(IteratorFeedbackKey.class, IteratorFeedbackCipher.class, IteratorFeedbackKeyCreator.class.getConstructor(args1), IteratorFeedbackKey.factory, IteratorFeedbackCipher.sfactory);
			add(AffineFeedbackKey.class, AffineFeedbackCipher.class, AffineFeedbackKeyCreator.class.getConstructor(args1), AffineFeedbackKey.factory, AffineFeedbackCipher.sfactory);
			add(PolybiusKey.class, PolybiusCipher.class, PolybiusKeyCreator.class.getConstructor(args1), PolybiusKey.factory, null);
			add(MultiPolybiusKey.class, MultiPolybius.class, MultiPolybiusKeyCreator.class.getConstructor(args1), MultiPolybiusKey.factory, MultiPolybius.sfactory);
			
		} catch (Exception e) {
			Log.err.println("Error: Problem instantiating Cipher Factories. Cipher Registry cannot be initialized.");
			e.printStackTrace();
			Runtime.getRuntime().halt(1);
		}
	}
	
	public static <Key extends ISecret<?>, Creator extends KeyCreatorPanel<Key>> void add(Class<Key> arg, Class<?> kcl, Constructor<Creator> pcon, KeyFactory<Key> kf, Object sfo) throws NoSuchMethodException, SecurityException
	{
		args0[0] = arg;
		Object ccono = kcl.getConstructor(args0);
		reg.add(new CipherFactory<ICipher<Key, IState<?>>, Key, Creator, IState<?>>((Constructor<ICipher<Key, IState<?>>>) ccono, pcon, kf, (Factory<IState<?>>) sfo));
	}
	
	public static String getName(int ID)
	{
		return names[ID];
	}
	
	public static ICipher<? extends ISecret<?>, IState<?>> getCipher(ISecret<?> key, int ID) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		return factories[ID].getCipher(key);
	}
	
	public static KeyCreatorPanel<?> getPanel(int ID) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		return factories[ID].newPanel();
	}
	
	public static Factory<? extends ISecret<?>> getFactory(int ID)
	{
		return factories[ID].getFactory();
	}
			
	public static Factory<? extends IState<?>> getStateFactory(int ID)
	{
		return factories[ID].getStateFactory();
	}
	
	public static ISecret<?> random(int ID, Alphabet ab)
	{
		return factories[ID].random(ab);
	}
	
}
