package claire.simplecrypt.ciphers.fraction;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;

public class PolybiusCipher 
	   implements ICipher<PolybiusKey, IState<?>> {

	private PolybiusKey key;
	private Alphabet ab;
	
	private byte[] row;
	private byte[] col;
	
	private byte[] buffer;
	
	public PolybiusCipher(PolybiusKey key) 
	{
		this.row = key.getSet1();
		this.col = key.getSet2();
		this.key = key;
		this.ab = key.getAlphabet();
	}

	public void encipher(byte[] plaintext, int start, int len)
	{
		if(buffer == null || buffer.length < len)
			buffer = new byte[len];
		System.arraycopy(plaintext, start, buffer, 0, len);
		int i = 0;
		while(len-- > 0) {
			plaintext[start++] = col[buffer[i  ] / row.length];
			plaintext[start++] = row[buffer[i++] % row.length];
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			ciphertext[start1++] = col[plaintext[start0  ] / row.length];
			ciphertext[start1++] = row[plaintext[start0++] % row.length];
		}
	}
	
	public void decipher(byte[] ciphertext, int start, int len)
	{
		int pos = start;
		while(len > 0) {
			int c = -1,
				r = -1, 
				i = 0;
			while(c == -1)
				if(col[i] == ciphertext[start]) 
					c = i;
				else
					i++;
			i = 0; start++;
			while(r == -1)
				if(row[i] == ciphertext[start]) 
					r = i;
				else
					i++;
			i = 0;
			start++;
			ciphertext[pos++] = (byte) (c * row.length + r);
			len -= 2;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len > 0) {
			int c = -1,
				r = -1, 
				i = 0;
			while(c == -1)
				if(col[i] == ciphertext[start0]) 
					c = i;
				else
					i++;
			i = 0; start0++;
			while(r == -1)
				if(row[i] == ciphertext[start0]) 
					r = i;
				else
					i++;
			i = 0;
			start0++;
			ciphertext[start1++] = (byte) (c * row.length + r);
			len -= 2;
		}
	}
	
	public int plaintextSize(int cipher)
	{
		return cipher / 2;
	}

	public int ciphertextSize(int plain)
	{
		return plain * 2;
	}

	public void reset() {}

	public void destroy()
	{
		this.ab = null;
		this.key = null;
		this.row = this.col = null;
	}

	public void loadState(IState<?> state) {}
	public void updateState(IState<?> state) {}
	
	public PolybiusKey getKey()
	{
		return this.key;
	}
	
	public void setKey(PolybiusKey key)
	{
		this.row = key.getSet1();
		this.col = key.getSet2();
		this.key = key;
		this.ab = key.getAlphabet();
	}
	
	public IState<?> getState()
	{
		return null;
	}

	public boolean hasState()
	{
		return false;
	}

	public Alphabet getAlphabet()
	{
		return this.ab;
	}
	
}
