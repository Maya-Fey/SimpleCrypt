package claire.simplecrypt.standards;

import claire.simplecrypt.data.Alphabet;

public interface ICipher<Key extends ISecret<?>>
	   extends IEncipherer<Key>,
	   		   IDecipherer<Key> {
	
	Alphabet getAlphabet();

}
