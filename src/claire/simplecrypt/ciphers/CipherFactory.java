package claire.simplecrypt.ciphers;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import claire.simplecrypt.display.KeyCreatorPanel;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;

public class CipherFactory<Cipher extends ICipher<Key>, Key extends ISecret<?>, Panel extends KeyCreatorPanel<Key>> {
	
	private final Constructor<Cipher> con0;
	private final Constructor<Panel> con1;
	private final Factory<Key> factory;
	
	public CipherFactory(Constructor<Cipher> con0, Constructor<Panel> con1, Factory<Key> factory) 
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

}
