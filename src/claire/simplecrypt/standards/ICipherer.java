package claire.simplecrypt.standards;

public interface ICipherer<Key extends ISecret<?>> {

	void reset();
	void setKey(Key key);
	void destroy();
	void loadState(IState<?> state);
	
	Key getKey();
	
	IState<?> getState();

}
