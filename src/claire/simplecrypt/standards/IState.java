package claire.simplecrypt.standards;

import claire.util.standards.IPersistable;
import claire.util.standards.IUUID;

public interface IState<State extends IState<State>> 
	   extends IPersistable<State>, 
	   		   IUUID<State> {

}
