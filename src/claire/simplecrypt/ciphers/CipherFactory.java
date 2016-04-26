package claire.simplecrypt.ciphers;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.display.creators.KeyCreatorPanel;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.IState;
import claire.util.crypto.rng.primitive.JRandom;
import claire.util.io.Factory;
import claire.util.standards.crypto.IRandom;

public class CipherFactory<Cipher extends ICipher<Key, State>, Key extends ISecret<?>, Panel extends KeyCreatorPanel<Key>, State extends IState<?>> {
	
	private static final IRandom<?> rand = new JRandom();
	
	private final Constructor<Cipher> con0;
	private final Constructor<Panel> con1;
	private final KeyFactory<Key> factory;
	private final Factory<State> sf;
	
	public CipherFactory(Constructor<Cipher> con0, Constructor<Panel> con1, KeyFactory<Key> factory, Factory<State> sf) 
	{
		this.con0 = con0;
		this.con1 = con1;
		this.factory = factory;
		this.sf = sf;
	}
	
	public ICipher<Key, State> getCipher(ISecret<?> key) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
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
	
	public Factory<State> getStateFactory()
	{
		return this.sf;
	}
	
	public Key random(Alphabet ab)
	{
		return factory.random(ab, rand);
	}

}
