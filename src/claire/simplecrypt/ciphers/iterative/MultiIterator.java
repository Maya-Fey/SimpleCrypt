package claire.simplecrypt.ciphers.iterative;

import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class MultiIterator 
	   implements ICipher<MultiIteratorKey, MultiIteratorState> {
	
	protected int[] eadd;
	protected int[] dadd;
	protected int epos = 0;
	protected int dpos = 0;

	private MultiIteratorKey master;
	private Alphabet ab;
	private int[] iterator;
	
	public MultiIterator(MultiIteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		int[] ints = key.getKey();
		eadd = new int[ints.length];
		dadd = new int[ints.length];
		this.iterator = ints;
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			eadd[epos] += iterator[epos];
			if(eadd[epos] >= ab.getLen())
				eadd[epos] -= ab.getLen();
			int n = plaintext[start] + eadd[epos];
			if(++epos == eadd.length)
				epos = 0;
			if(n >= ab.getLen())
				n -= ab.getLen();
			plaintext[start++] = (byte) n;
		}
	}
	
	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			eadd[epos] += iterator[epos];
			if(eadd[epos] >= ab.getLen())
				eadd[epos] -= ab.getLen();
			int n = plaintext[start0++] + eadd[epos];
			if(++epos == eadd.length)
				epos = 0;
			if(n >= ab.getLen())
				n -= ab.getLen();
			ciphertext[start1++] = (byte) n;
		}
	}
	
	public int ciphertextSize(int plain)
	{
		return plain;
	}

	public void reset()
	{
		epos = dpos = 0;
		Arrays.fill(eadd, 0);
		Arrays.fill(dadd, 0);
	}

	public void setKey(MultiIteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		int[] ints = master.getKey();
		if(ints.length != eadd.length) {
			eadd = new int[ints.length];
			dadd = new int[ints.length];
		}
		iterator = ints;
		epos = dpos = 0;
	}

	public void destroy()
	{
		master = null;
		ab = null;
		dpos = epos = 0;
		Arrays.fill(eadd, 0);
		Arrays.fill(dadd, 0);
		eadd = dadd = iterator = null;
	}

	public MultiIteratorKey getKey()
	{
		return master;
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			dadd[dpos] += iterator[dpos];
			if(dadd[dpos] >= ab.getLen())
				dadd[dpos] -= ab.getLen();
			int n = ciphertext[start] - dadd[dpos];
			if(++dpos == dadd.length)
				dpos = 0;
			if(n < 0)
				n += ab.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			dadd[dpos] += iterator[dpos];
			if(dadd[dpos] >= ab.getLen())
				dadd[dpos] -= ab.getLen();
			int n = ciphertext[start0++] - dadd[dpos];
			if(++dpos == dadd.length)
				dpos = 0;
			if(n < 0)
				n += ab.getLen();
			plaintext[start1++] = (byte) n;
		}
	}

	public int plaintextSize(int cipher)
	{
		return cipher;
	}

	public Alphabet getAlphabet()
	{
		return ab;
	}
	
	public void loadState(MultiIteratorState state)
	{
		epos = state.epos;
		dpos = state.dpos;
		System.arraycopy(state.eadd, 0, eadd, 0, eadd.length);
		System.arraycopy(state.dadd, 0, dadd, 0, dadd.length);
	}

	public void updateState(MultiIteratorState state)
	{
		state.epos = epos;
		state.dpos = dpos;
		System.arraycopy(eadd, 0, state.eadd, 0, eadd.length);
		System.arraycopy(dadd, 0, state.dadd, 0, dadd.length);
	}

	public MultiIteratorState getState()
	{
		return new MultiIteratorState(this);
	}

	public boolean hasState()
	{
		return true;
	}

}
