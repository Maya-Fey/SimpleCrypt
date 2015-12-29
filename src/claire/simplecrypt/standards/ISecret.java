package claire.simplecrypt.standards;

import claire.util.standards.IPersistable;

public interface ISecret<Key>
	   extends IPersistable<Key> {
	
	char[] getAlphabet();
	
	void destroy();

}
