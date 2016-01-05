package claire.simplecrypt.standards;

import claire.simplecrypt.data.Alphabet;
import claire.util.standards.IPersistable;
import claire.util.standards.IReferrable;
import claire.util.standards.IUUID;

public interface ISecret<Key extends ISecret<Key>>
	   extends IPersistable<Key>,
	   		   IUUID<Key>,
	   		   IReferrable<Key> {
	
	Alphabet getAlphabet();
	
	void destroy();

}
