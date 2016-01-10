package claire.simplecrypt.ciphers;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;

public class CipherFactory<Cipher extends ICipher<Key>, Key extends ISecret<Key>> {

	private final Constructor<Cipher> con;
	
	public CipherFactory(Constructor<Cipher> con) 
	{
		this.con = con;
	}
	
	public Cipher getCipher(ISecret<?> key) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		return con.newInstance(key);
	}

}
