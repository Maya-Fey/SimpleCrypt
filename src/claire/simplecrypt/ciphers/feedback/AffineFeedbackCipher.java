package claire.simplecrypt.ciphers.feedback;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.feedback.AffineFeedbackCipher.AffineFeedbackState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class AffineFeedbackCipher 
	   implements ICipher<AffineFeedbackKey, AffineFeedbackState> {
	
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
	
	public boolean hasState()
	{
		return true;
	}
	
	public void loadState(AffineFeedbackState state)
	{
		this.dpos = state.dpos;
		this.epos = state.epos;
		System.arraycopy(state.dkey, 0, dkey, 0, dkey.length);
		System.arraycopy(state.ekey, 0, ekey, 0, ekey.length);
	}
	
	public void updateState(AffineFeedbackState state)
	{
		state.dpos = this.dpos;
		state.epos = this.epos;
		System.arraycopy(dkey, 0, state.dkey, 0, dkey.length);
		System.arraycopy(ekey, 0, state.ekey, 0, ekey.length);
	}

	public AffineFeedbackState getState()
	{
		return new AffineFeedbackState(this);
	}
	
	public static final Factory<AffineFeedbackState> sfactory = new AffineFeedbackStateFactory();
	
	public static final class AffineFeedbackState implements IState<AffineFeedbackState>
	{
		private final int[] ekey;
		private final int[] dkey;
		
		private int epos;
		private int dpos;
		
		private AffineFeedbackState(int epos, int dpos, int[] ekey, int[] dkey)
		{
			this.epos = epos;
			this.dpos = dpos;
			this.ekey = ekey;
			this.dkey = dkey;
		}
		
		public AffineFeedbackState(AffineFeedbackCipher c)
		{
			this.ekey = c.ekey;
			this.dkey = c.dkey;
			this.epos = c.epos;
			this.dpos = c.dpos;
		}
		
		public int NAMESPACE()
		{
			return NamespaceKey.AFFINEFEEDBACKSTATE;
		}

		public boolean sameAs(AffineFeedbackState obj)
		{
			return (epos == obj.dpos && obj.epos == obj.dpos) && (ArrayUtil.equals(ekey, obj.ekey) && ArrayUtil.equals(dkey, obj.dkey));
		}

		public void export(IOutgoingStream stream) throws IOException
		{
			stream.writeInt(epos);
			stream.writeInt(dpos);
			stream.writeInt(ekey.length);
			stream.writeInts(ekey);
			stream.writeInts(dkey);
		}

		public void export(byte[] bytes, int offset)
		{
			Bits.intToBytes(epos, bytes, offset); offset += 4;
			Bits.intToBytes(dpos, bytes, offset); offset += 4;
			Bits.intToBytes(ekey.length, bytes, offset); offset += 4;
			offset = IOUtils.writeArr(ekey, bytes, offset);
			IOUtils.writeArr(dkey, bytes, offset);
		}

		public int exportSize()
		{
			return 4 * ekey.length + 12;
		}

		public Factory<AffineFeedbackState> factory()
		{
			return sfactory;
		}

	}
	
	private static final class AffineFeedbackStateFactory extends Factory<AffineFeedbackState>
	{

		protected AffineFeedbackStateFactory() 
		{
			super(AffineFeedbackState.class);
		}

		public AffineFeedbackState resurrect(byte[] data, int start) throws InstantiationException
		{
			int ep = Bits.intFromBytes(data, start); start += 4;
			int dp = Bits.intFromBytes(data, start); start += 4;
			int len = Bits.intFromBytes(data, start); start += 4;
			int[] ek = IOUtils.readIntArr(data, start); start += 4 * len;
			int[] dk = IOUtils.readIntArr(data, start); 
			return new AffineFeedbackState(ep, dp, ek, dk);
		}

		public AffineFeedbackState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int ep = stream.readInt();
			int dp = stream.readInt();
			int[] ek = stream.readIntArr();
			int[] dk = stream.readInts(ek.length);
			return new AffineFeedbackState(ep, dp, ek, dk);
		}
		
	}

}
