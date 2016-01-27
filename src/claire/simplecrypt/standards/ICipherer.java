package claire.simplecrypt.standards;

public interface ICipherer<Key extends ISecret<?>, State extends IState<?>> {

	void reset();
	void setKey(Key key);
	void destroy();
	void loadState(State state);
	void updateState(State state);
	
	Key getKey();
	State getState();
	
	boolean hasState();

}
