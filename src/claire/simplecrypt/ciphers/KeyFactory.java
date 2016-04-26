package claire.simplecrypt.ciphers;

import claire.simplecrypt.data.Alphabet;
import claire.util.io.Factory;
import claire.util.standards.crypto.IRandom;

public abstract class KeyFactory<Key> extends Factory<Key> {

	public KeyFactory(Class<Key> class_)
	{
		super(class_);
	}
	
	public abstract Key random(Alphabet ab, IRandom<?> rand);

}
