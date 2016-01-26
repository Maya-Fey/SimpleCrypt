package claire.simplecrypt.ciphers;

import java.lang.reflect.InvocationTargetException;

import claire.simplecrypt.ciphers.autokey.AutoKeyCipher;
import claire.simplecrypt.ciphers.autokey.AutoKeyKey;
import claire.simplecrypt.ciphers.ceasar.CeasarCipher;
import claire.simplecrypt.ciphers.ceasar.CeasarKey;
import claire.simplecrypt.ciphers.ceasar.MultiCeasar;
import claire.simplecrypt.ciphers.ceasar.MultiCeasarKey;
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
import claire.simplecrypt.ciphers.substitution.SubstitutionCipher;
import claire.simplecrypt.ciphers.substitution.SubstitutionKey;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.creators.AffineKeyCreator;
import claire.simplecrypt.display.creators.AutoKeyKeyCreator;
import claire.simplecrypt.display.creators.CeasarKeyCreator;
import claire.simplecrypt.display.creators.IterativeKeyCreator;
import claire.simplecrypt.display.creators.IteratorKeyCreator;
import claire.simplecrypt.display.creators.KeyCreatorPanel;
import claire.simplecrypt.display.creators.MultiAffineKeyCreator;
import claire.simplecrypt.display.creators.MultiCeasarKeyCreator;
import claire.simplecrypt.display.creators.MultiIterativeKeyCreator;
import claire.simplecrypt.display.creators.MultiIteratorKeyCreator;
import claire.simplecrypt.display.creators.SubstitutionKeyCreator;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.IState;
import claire.util.io.Factory;
import claire.util.logging.Log;

public final class CipherRegistry {
	
	private static final Class<?>[] args0 = new Class<?>[] 
		{
			ISecret.class
		};
	
	private static final Class<?>[] args1 = new Class<?>[]
		{
		
		};
	
	private static final CipherFactory<?, ? extends ISecret<?>, ? extends KeyCreatorPanel<?>, ? extends IState<?>>[] factories = new CipherFactory<?, ?, ?, ?>[10];
	
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
			"Substitution Cipher"
		};
	
	static {
		try {
			args0[0] = CeasarKey.class;
			factories[0] = new CipherFactory<CeasarCipher, CeasarKey, CeasarKeyCreator>(CeasarCipher.class.getConstructor(args0), CeasarKeyCreator.class.getConstructor(args1), CeasarKey.factory);
			args0[0] = MultiCeasarKey.class;
			factories[1] = new CipherFactory<MultiCeasar, MultiCeasarKey, MultiCeasarKeyCreator>(MultiCeasar.class.getConstructor(args0), MultiCeasarKeyCreator.class.getConstructor(args1), MultiCeasarKey.factory);
			args0[0] = AutoKeyKey.class;
			factories[2] = new CipherFactory<AutoKeyCipher, AutoKeyKey, AutoKeyKeyCreator>(AutoKeyCipher.class.getConstructor(args0), AutoKeyKeyCreator.class.getConstructor(args1), AutoKeyKey.factory);
			args0[0] = IteratorKey.class;
			factories[3] = new CipherFactory<IterativeCipher, IteratorKey, IterativeKeyCreator>(IterativeCipher.class.getConstructor(args0), IterativeKeyCreator.class.getConstructor(args1), IteratorKey.factory);
			args0[0] = IteratorKey.class;
			factories[4] = new CipherFactory<IteratorCipher, IteratorKey, IteratorKeyCreator>(IteratorCipher.class.getConstructor(args0), IteratorKeyCreator.class.getConstructor(args1), IteratorKey.factory);
			args0[0] = MultiIteratorKey.class;
			factories[5] = new CipherFactory<MultiIterative, MultiIteratorKey, MultiIterativeKeyCreator>(MultiIterative.class.getConstructor(args0), MultiIterativeKeyCreator.class.getConstructor(args1), MultiIteratorKey.factory);
			args0[0] = MultiIteratorKey.class;
			factories[6] = new CipherFactory<MultiIterator, MultiIteratorKey, MultiIteratorKeyCreator>(MultiIterator.class.getConstructor(args0), MultiIteratorKeyCreator.class.getConstructor(args1), MultiIteratorKey.factory);
			args0[0] = AffineKey.class;
			factories[7] = new CipherFactory<AffineCipher, AffineKey, AffineKeyCreator>(AffineCipher.class.getConstructor(args0), AffineKeyCreator.class.getConstructor(args1), AffineKey.factory);
			args0[0] = MultiAffineKey.class;
			factories[8] = new CipherFactory<MultiAffine, MultiAffineKey, MultiAffineKeyCreator>(MultiAffine.class.getConstructor(args0), MultiAffineKeyCreator.class.getConstructor(args1), MultiAffineKey.factory);
			args0[0] = SubstitutionKey.class;
			factories[9] = new CipherFactory<SubstitutionCipher, SubstitutionKey, SubstitutionKeyCreator>(SubstitutionCipher.class.getConstructor(args0), SubstitutionKeyCreator.class.getConstructor(args1), SubstitutionKey.factory);
			
		} catch (Exception e) {
			Log.err.println("Error: Problem instantiating Cipher Factories. Cipher Registry cannot be initialized.");
			e.printStackTrace();
			Runtime.getRuntime().halt(1);
		}
	}
	
	static void init() throws Exception
	{
		throw new Exception();
	}
	
	public static String getName(int ID)
	{
		return names[ID];
	}
	
	public static ICipher<? extends ISecret<?>> getCipher(ISecret<?> key, int ID) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
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
