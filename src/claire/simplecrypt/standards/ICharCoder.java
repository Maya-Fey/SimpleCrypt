package claire.simplecrypt.standards;

public interface ICharCoder 
	   extends ICharDecoder, 
	   		   ICharEncoder {

	ICipher<?, ?> getCipher();
	void setCipher(ICipher<?, ?> cipher);
}
