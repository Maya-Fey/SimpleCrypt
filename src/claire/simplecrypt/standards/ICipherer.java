package claire.simplecrypt.standards;

public interface ICipherer<Key extends ISecret<?>> {

	void reset();
	void setKey(Key key);
	void destroy();
	
	Key getKey();

}
