package claire.simplecrypt.standards;

import claire.simplecrypt.data.Alphabet;

public interface ICipher<Key extends ISecret<?>, State extends IState<?>>
	   extends IEncipherer<Key, State>,
	   		   IDecipherer<Key, State> {
	
	Alphabet getAlphabet();

}
