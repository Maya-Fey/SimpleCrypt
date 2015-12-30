package claire.simplecrypt.standards;

public interface ICipher<Key extends ISecret<Key>>
	   extends IEncipherer<Key>,
	   		   IDecipherer<Key> {

}
