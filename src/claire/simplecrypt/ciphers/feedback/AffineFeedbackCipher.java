package claire.simplecrypt.ciphers.feedback;

import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class AffineFeedbackCipher 
	   implements ICipher<AffineFeedbackKey> {
	
	private AffineFeedbackKey key;
	private Alphabet alphabet;
	private int[] ekey;
	private int[] dkey;
	private int[] mul;
	private int epos = 0;
	private int dpos = 0;
	
	public AffineFeedbackCipher(AffineFeedbackKey key)
	{
		this.key = key;
		this.alphabet = key.getAlphabet();
		int[] ints = key.getAdd();
		mul = key.getMul();
		ekey = new int[ints.length];
		dkey = new int[ints.length];
		System.arraycopy(ints, 0, ekey, 0, ints.length);
		System.arraycopy(ints, 0, dkey, 0, ints.length);
	}

	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + ekey[epos];
			ekey[epos] *= mul[epos];
			ekey[epos] += plaintext[start];
			ekey[epos] %= alphabet.getLen();
			epos++;
			if(epos == ekey.length)
				epos = 0;
			if(n >= alphabet.getLen())
				n -= alphabet.getLen();
			plaintext[start++] = (byte) n;
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start0] + ekey[epos];
			ekey[epos] *= mul[epos];
			ekey[epos] += plaintext[start0++];
			ekey[epos] %= alphabet.getLen();
			epos++;
			if(epos == ekey.length)
				epos = 0;
			if(n >= alphabet.getLen())
				n -= alphabet.getLen();
			ciphertext[start1++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start] - dkey[dpos];
			if(n < 0)
				n += alphabet.getLen();
			dkey[dpos] *= mul[dpos];
			dkey[dpos] += ciphertext[start++] = (byte) n;
			dkey[dpos] %= alphabet.getLen();
			dpos++;
			if(dpos == ekey.length)
				dpos = 0;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start0++] - dkey[dpos];
			if(dpos == ekey.length)
				dpos = 0;
			if(n < 0)
				n += alphabet.getLen();
			dkey[dpos] *= mul[dpos];
			dkey[dpos] += ciphertext[start1++] = (byte) n;
			dkey[dpos] %= alphabet.getLen();
			dpos++;
			if(dpos == ekey.length)
				dpos = 0;
		}
	}
	
	public void reset() 
	{
		int[] ints = key.getAdd();
		System.arraycopy(ints, 0, ekey, 0, ints.length);
		System.arraycopy(ints, 0, dkey, 0, ints.length);
		this.epos = 0;
		this.dpos = 0;
	}

	public void setKey(AffineFeedbackKey key)
	{
		int[] ints = key.getAdd();
		mul = key.getMul();
		/*
		 * Small note: Adding internal length param would make this more efficient
		 */
		if(ints.length != ekey.length) {
			ekey = new int[ints.length];
			dkey = new int[ints.length];
		}
		System.arraycopy(ints, 0, ekey, 0, ints.length);
		System.arraycopy(ints, 0, dkey, 0, ints.length);
		this.key = key;
		this.epos = 0;
		this.dpos = 0;
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.epos = 0;
		this.dpos = 0;
		this.alphabet = null;
		Arrays.fill(ekey, 0);
		Arrays.fill(dkey, 0);
		ekey = dkey = mul = null;
	}

	public AffineFeedbackKey getKey()
	{
		return this.key;
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
		return alphabet;
	}

}
