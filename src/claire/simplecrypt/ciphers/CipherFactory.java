package claire.simplecrypt.ciphers;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.creators.KeyCreatorPanel;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.util.crypto.rng.primitive.JRandom;
import claire.util.io.Factory;
import claire.util.standards.IRandom;

public class CipherFactory<Cipher extends ICipher<Key>, Key extends ISecret<?>, Panel extends KeyCreatorPanel<Key>> {
	
	private static final IRandom rand = new JRandom();
	
	private final Constructor<Cipher> con0;
	private final Constructor<Panel> con1;
	private final KeyFactory<Key> factory;
	
	public CipherFactory(Constructor<Cipher> con0, Constructor<Panel> con1, KeyFactory<Key> factory) 
	{
		this.con0 = con0;
		this.con1 = con1;
		this.factory = factory;
	}
	
	public Cipher getCipher(ISecret<?> key) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		return con0.newInstance(key);
	}
	
	public Panel newPanel() throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		return con1.newInstance();
	}
	
	public Factory<Key> getFactory()
	{
		return factory;
	}
	
	public Key random(Alphabet ab)
	{
		return factory.random(ab, rand);
	}

}
