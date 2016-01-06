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
		int pos = 0,
			start1 = start;
		while(len-- > 0) 
		{
			byte to = ab.convertTo(temp[start++]);
			if(to == -1) 
				if(pos != 0) {
					cipher.decipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, plaintext, start1, pos);
					start1 += pos;
				} else
					start1++;
			else
				buffer[pos++] = to;
		}
		if(pos != 0) {
			cipher.decipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, plaintext, start1, pos);
		} 
	}

	public void decode(char[] plaintext, int start0, char[] codetext, int start1, int len)
	{
		int pos = 0;
		while(len-- > 0) 
		{
			byte to = ab.convertTo(plaintext[start0++]);
			if(to == -1) 
				if(pos != 0) {
					cipher.decipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, codetext, start1, pos);
					start1 += pos;
				} else
					start1++;
			else
				buffer[pos++] = to;
		}
		if(pos != 0) {
			cipher.decipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, codetext, start1, pos);
		} 
	}

	public IDecipherer<?> getDecipherer()
	{
		return cipher;
	}

	public void encode(char[] plaintext, int start, int len)
	{
		int pos = 0,
			start1 = start;
		while(len-- > 0) 
		{
			byte to = ab.convertTo(plaintext[start++]);
			if(to == -1) 
				if(pos != 0) {
					cipher.encipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, plaintext, start1, pos);
					start1 += pos;
				} else
					start1++;
			else
				buffer[pos++] = to;
		}
		if(pos != 0) {
			cipher.encipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, plaintext, start1, pos);
		} 
	}
	
	public void encode(char[] plaintext, int start0, char[] codetext, int start1, int len)
	{
		int pos = 0;
		while(len-- > 0) 
		{
			byte to = ab.convertTo(plaintext[start0++]);
			if(to == -1) 
				if(pos != 0) {
					cipher.encipher(buffer, 0, pos);
					ab.convertFrom(buffer, 0, codetext, start1, pos);
					start1 += pos;
				} else
					start1++;
			else
				buffer[pos++] = to;
		}
		if(pos != 0) {
			cipher.encipher(buffer, 0, pos);
			ab.convertFrom(buffer, 0, codetext, start1, pos);
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
