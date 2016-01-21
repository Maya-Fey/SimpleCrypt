package claire.simplecrypt.ciphers;

import claire.util.io.Factory;
import claire.util.standards.IRandom;

public abstract class KeyFactory<Key> extends Factory<Key> {

	public KeyFactory(Class<Key> class_)
	{
		super(class_);
	}
	
	public abstract Key random(IRandom rand);

}
