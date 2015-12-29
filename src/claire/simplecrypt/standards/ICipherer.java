package claire.simplecrypt.standards;

public interface ICipherer<Key> {

	void reset();
	void setKey(Key key);
	void destroy();
	
	Key getKey();

}
