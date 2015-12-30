package claire.simplecrypt.standards;

import claire.util.standards.IPersistable;
import claire.util.standards.IReferrable;
import claire.util.standards.IUUID;

public interface ISecret<Key extends ISecret<Key>>
	   extends IPersistable<Key>,
	   		   IUUID<Key>,
	   		   IReferrable<Key> {
	
	char[] getAlphabet();
	
	void destroy();

}
