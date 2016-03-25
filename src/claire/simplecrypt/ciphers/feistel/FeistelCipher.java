package claire.simplecrypt.ciphers.feistel;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.util.memory.Bits;

public class FeistelCipher 
	   implements ICipher<FeistelKey, IState<?>> {
	
	private FeistelKey mkey;
	private Alphabet ab;
	private byte[] key;
	
	public FeistelCipher(FeistelKey key)
	{
		this.mkey = key;
		this.ab = key.getAlphabet();
		this.key = key.getKey();
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len > key.length)
		{
			for(int i = 0; i < key.length; i++)
			{
				plaintext[start] = (byte) ((plaintext[start] + plaintext[start + 1] + key[i]) % ab.getLen());
				Bits.rotateLeft1(plaintext, start, key.length);
			}
			start += key.length;
			len -= key.length;
		}
		if(len > 0)
		{
			for(int i = 0; i < len; i++)
			{
				if(len > 1)
					plaintext[start] = (byte) ((plaintext[start] + plaintext[start + 1] + key[i]) % ab.getLen());
				else
					plaintext[start] = (byte) ((plaintext[start] + key[i]) % ab.getLen());
				Bits.rotateLeft1(plaintext, start, len);
			}
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		System.arraycopy(plaintext, start0, ciphertext, start1, len);
		this.encipher(ciphertext, start1, len);
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len > key.length)
		{
			int base = start + key.length - 1;
			for(int i = key.length; i > 0;)
			{
				ciphertext[base] = (byte) (ciphertext[base] - ((ciphertext[start] + key[--i]) % ab.getLen()));
				if(ciphertext[base] < 0)
					ciphertext[base] += ab.getLen();
				Bits.rotateRight1(ciphertext, start, key.length);
			}
			start += key.length;
			len -= key.length;
		}
		if(len > 0)
		{
			int base = start + len - 1;
			for(int i = len; i > 0;)
			{
				if(len > 1)
					ciphertext[base] = (byte) (ciphertext[base] - ((ciphertext[start] + key[--i]) % ab.getLen()));
				else
					ciphertext[base] = (byte) (ciphertext[base] - key[--i]);
				if(ciphertext[base] < 0)
					ciphertext[base] += ab.getLen();
				Bits.rotateRight1(ciphertext, start, len);
			}
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		System.arraycopy(ciphertext, start0, plaintext, start1, len);
		this.decipher(plaintext, start1, len);
	}
	
	public FeistelKey getKey()
	{
		return this.mkey;
	}
	
	public void setKey(FeistelKey key)
	{
		this.mkey = key;
		this.ab = key.getAlphabet();
		this.key = key.getKey();
	}

	public void reset() {}
	public IState<?> getState() { return null; }
	public void loadState(IState<?> state) {}
	public void updateState(IState<?> state) {}

	public boolean hasState()
	{
		return true;
	}

	public int ciphertextSize(int plain)
	{
		return plain;
	}
	
	public int plaintextSize(int cipher)
	{
		return cipher;
	}

	public Alphabet getAlphabet()
	{
		return this.ab;
	}
	
	public void destroy()
	{
		this.mkey = null;
		this.ab = null;
		this.key = null;
	}
	
}
