package claire.simplecrypt.ciphers;

import java.lang.reflect.InvocationTargetException;

import claire.simplecrypt.ciphers.ceasar.CeasarCipher;
import claire.simplecrypt.ciphers.ceasar.CeasarKey;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.util.logging.Log;
import claire.util.standards.IPersistable;

public final class CipherRegistry {
	
	private static final Class<?>[] args = new Class<?>[] 
		{
			ISecret.class
		};

	private static final CipherFactory<?, ? extends ISecret<?>>[] factories = new CipherFactory<?, ?>[1];
	
	private static final String[] names = new String[]
		{
			"CeasarCipher" 
		};
	
	static {
		try {
			factories[0] = new CipherFactory<CeasarCipher, CeasarKey>(CeasarCipher.class.getConstructor(args));
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
	
	public static ICipher<?> getCipher(ISecret<?> key, int ID) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		return factories[ID].getCipher(key);
	}
}
