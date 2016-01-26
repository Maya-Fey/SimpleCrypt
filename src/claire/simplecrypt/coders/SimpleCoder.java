package claire.simplecrypt.coders;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IDecipherer;
import claire.simplecrypt.standards.IEncipherer;

public class SimpleCoder 
	   implements ICharCoder {

	private ICipher<?, ?> cipher;
	private Alphabet ab;
	private byte[] buffer;
	
	public SimpleCoder(ICipher<?, ?> cipher, byte[] buffer)
	{
		this.cipher = cipher;
		this.ab = cipher.getAlphabet();
		this.buffer = buffer;
	}
	
	public SimpleCoder(ICipher<?, ?> cipher, int start)
	{
		this.cipher = cipher;
		this.ab = cipher.getAlphabet();
		this.buffer = new byte[start];
	}
	
	public void decode(char[] plaintext, int start, int len)
	{
		ab.convertTo(plaintext, start, buffer, 0, len);
		cipher.decipher(buffer, 0, len);
		ab.convertFrom(buffer, 0, plaintext, start, cipher.plaintextSize(len));
	}

	public void decode(char[] plaintext, int start0, char[] codetext, int start1, int len)
	{
		ab.convertTo(plaintext, start0, buffer, 0, len);
		cipher.decipher(buffer, 0, len);
		ab.convertFrom(buffer, 0, codetext, start1, cipher.plaintextSize(len));
	}

	public IDecipherer<?, ?> getDecipherer()
	{
		return cipher;
	}

	public void encode(char[] plaintext, int start, int len)
	{
		ab.convertTo(plaintext, start, buffer, 0, len);
		cipher.encipher(buffer, 0, len);
		ab.convertFrom(buffer, 0, plaintext, start, cipher.ciphertextSize(len));
	}
	
	public void encode(char[] plaintext, int start0, char[] codetext, int start1, int len)
	{
		ab.convertTo(plaintext, start0, buffer, 0, len);
		cipher.encipher(buffer, 0, len);
		ab.convertFrom(buffer, 0, codetext, start1, cipher.ciphertextSize(len));
	}
 
	public IEncipherer<?, ?> getEncipherer()
	{
		return cipher;
	}

	public ICipher<?, ?> getCipher()
	{
		return cipher;
	}
	
	public void setCipher(ICipher<?, ?> cipher)
	{
		this.cipher = cipher;
		this.ab = cipher.getAlphabet();
	}

}
