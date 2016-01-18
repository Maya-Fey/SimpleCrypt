package claire.simplecrypt.coders;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICharCoder;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IDecipherer;
import claire.simplecrypt.standards.IEncipherer;

public class IgnoreCoder 
	   implements ICharCoder {

	private ICipher<?> cipher;
	private Alphabet ab;
	private byte[] buffer;
	private char[] temp;
	
	public IgnoreCoder(ICipher<?> cipher, byte[] buffer)
	{
		this.cipher = cipher;
		this.ab = cipher.getAlphabet();
		this.buffer = buffer;
	}
	
	public IgnoreCoder(ICipher<?> cipher, int start)
	{
		this.cipher = cipher;
		this.ab = cipher.getAlphabet();
		this.buffer = new byte[start];
	}
	
	public void decode(char[] plaintext, int start, int len)
	{
		if(temp == null || len > temp.length)
			temp = new char[len];
		if(buffer.length < cipher.plaintextSize(len))
			buffer = new byte[cipher.plaintextSize(len)];
		System.arraycopy(plaintext, start, temp, 0, len);
		int i = 0,
			pos = 0;
		while(len-- > 0) 
		{
			byte coded = ab.convertTo(temp[i]);
			if(coded == -1) {
				if(pos != 0) {
					int x = cipher.plaintextSize(pos);
					cipher.decipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, plaintext, start, x);
					start += x;
					pos = 0;
				}
				plaintext[start++] = temp[i];
			} else {
				buffer[pos++] = coded;
			}
			i++;
		}
		if(pos != 0) {
			int x = cipher.plaintextSize(pos);
			cipher.decipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, plaintext, start, x);
		}
	}

	public void decode(char[] plaintext, int start0, char[] codetext, int start1, int len)
	{
		if(buffer.length < cipher.plaintextSize(len))
			buffer = new byte[cipher.plaintextSize(len)];
		int pos = 0;
		while(len-- > 0) 
		{
			byte coded = ab.convertTo(plaintext[start0]);
			if(coded == -1) {
				if(pos != 0) {
					int x = cipher.plaintextSize(pos);
					cipher.decipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, codetext, start1, x);
					start1 += x;
					pos = 0;
				}
				codetext[start1++] = plaintext[start0];
			} else {
				buffer[pos++] = coded;
			}
			start0++;
		}
		if(pos != 0) {
			int x = cipher.plaintextSize(pos);
			cipher.decipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, codetext, start1, x);
		}
	}

	public IDecipherer<?> getDecipherer()
	{
		return cipher;
	}

	public void encode(char[] plaintext, int start, int len)
	{
		if(temp == null || len > temp.length)
			temp = new char[len];
		if(buffer.length < cipher.ciphertextSize(len))
			buffer = new byte[cipher.ciphertextSize(len)];
		System.arraycopy(plaintext, start, temp, 0, len);
		int i = 0,
			pos = 0;
		while(len-- > 0) 
		{
			byte coded = ab.convertTo(temp[i]);
			if(coded == -1) {
				if(pos != 0) {
					int x = cipher.ciphertextSize(pos);
					cipher.encipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, plaintext, start, x);
					start += x;
					pos = 0;
				}
				plaintext[start++] = temp[i];
			} else {
				buffer[pos++] = coded;
			}
			i++;
		}
		if(pos != 0) {
			int x = cipher.ciphertextSize(pos);
			cipher.encipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, plaintext, start, x);
		}
	}
	
	public void encode(char[] plaintext, int start0, char[] codetext, int start1, int len)
	{
		if(buffer.length < cipher.ciphertextSize(len))
			buffer = new byte[cipher.ciphertextSize(len)];
		int pos = 0;
		while(len-- > 0) 
		{
			byte coded = ab.convertTo(plaintext[start0]);
			if(coded == -1) {
				if(pos != 0) {
					int x = cipher.ciphertextSize(pos);
					cipher.encipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, codetext, start1, x);
					start1 += x;
					pos = 0;
				}
				codetext[start1++] = plaintext[start0];
			} else {
				buffer[pos++] = coded;
			}
			start0++;
		}
		if(pos != 0) {
			int x = cipher.ciphertextSize(pos);
			cipher.encipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, codetext, start1, x);
		}
	}
 
	public IEncipherer<?> getEncipherer()
	{
		return cipher;
	}

	public ICipher<?> getCipher()
	{
		return cipher;
	}
	
	public void setCipher(ICipher<?> cipher)
	{
		this.cipher = cipher;
		this.ab = cipher.getAlphabet();
	}

}
