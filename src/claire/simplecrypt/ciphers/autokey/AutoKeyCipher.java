package claire.simplecrypt.ciphers.autokey;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.autokey.AutoKeyCipher.AutoKeyState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class AutoKeyCipher 
	   implements ICipher<AutoKeyKey, AutoKeyState> {
	
	private AutoKeyKey key;
	private Alphabet alphabet;
	private int[] ekey;
	private int[] dkey;
	private int epos = 0;
	private int dpos = 0;
	
	public AutoKeyCipher(AutoKeyKey key)
	{
		this.key = key;
		this.alphabet = key.getAlphabet();
		int[] ints = key.getKey();
		ekey = new int[ints.length];
		dkey = new int[ints.length];
		System.arraycopy(ints, 0, ekey, 0, ints.length);
		System.arraycopy(ints, 0, dkey, 0, ints.length);
	}

	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + ekey[epos];
			ekey[epos++] = plaintext[start];
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
			ekey[epos++] = plaintext[start0++];
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
			dkey[dpos++] = ciphertext[start++] = (byte) n;
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
			dkey[dpos++] = plaintext[start1++] = (byte) n;
			if(dpos == ekey.length)
				dpos = 0;
		}
	}
	
	public void reset() 
	{
		int[] ints = key.getKey();
		System.arraycopy(ints, 0, ekey, 0, ints.length);
		System.arraycopy(ints, 0, dkey, 0, ints.length);
		this.epos = 0;
		this.dpos = 0;
	}

	public void setKey(AutoKeyKey key)
	{
		int[] ints = key.getKey();
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
		ekey = dkey = null;
	}

	public AutoKeyKey getKey()
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
	
	public void loadState(AutoKeyState state)
	{
		this.dpos = state.dpos;
		this.epos = state.epos;
		System.arraycopy(state.dkey, 0, dkey, 0, dkey.length);
		System.arraycopy(state.ekey, 0, ekey, 0, ekey.length);
	}
	
	public void updateState(AutoKeyState state)
	{
		state.dpos = this.dpos;
		state.epos = this.epos;
		System.arraycopy(dkey, 0, state.dkey, 0, dkey.length);
		System.arraycopy(ekey, 0, state.ekey, 0, ekey.length);
	}

	public AutoKeyState getState()
	{
		return new AutoKeyState(this);
	}
	
	public static final Factory<AutoKeyState> sfactory = new AutoKeyStateFactory();
	
	public static final class AutoKeyState implements IState<AutoKeyState>
	{
		private final int[] ekey;
		private final int[] dkey;
		
		private int epos;
		private int dpos;
		
		private AutoKeyState(int epos, int dpos, int[] ekey, int[] dkey)
		{
			this.epos = epos;
			this.dpos = dpos;
			this.ekey = ekey;
			this.dkey = dkey;
		}
		
		public AutoKeyState(AutoKeyCipher c)
		{
			this.ekey = ArrayUtil.copy(c.ekey);
			this.dkey = ArrayUtil.copy(c.dkey);
			this.epos = c.epos;
			this.dpos = c.dpos;
		}
		
		public int NAMESPACE()
		{
			return NamespaceKey.AUTOKEYSTATE;
		}

		public boolean sameAs(AutoKeyState obj)
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
			Bits.intsToBytes(ekey, 0, bytes, offset, ekey.length); offset += 4 * ekey.length;
			Bits.intsToBytes(dkey, 0, bytes, offset, dkey.length);
		}

		public int exportSize()
		{
			return 8 * ekey.length + 12;
		}

		public Factory<AutoKeyState> factory()
		{
			return sfactory;
		}

	}
	
	private static final class AutoKeyStateFactory extends Factory<AutoKeyState>
	{

		protected AutoKeyStateFactory() 
		{
			super(AutoKeyState.class);
		}

		public AutoKeyState resurrect(byte[] data, int start) throws InstantiationException
		{
			int ep = Bits.intFromBytes(data, start); start += 4;
			int dp = Bits.intFromBytes(data, start); start += 4;
			int len = Bits.intFromBytes(data, start); start += 4;
			int[] ek = new int[len];
			int[] dk = new int[len];
			Bits.bytesToInts(data, start, ek, 0, len); start += len * 4;
			Bits.bytesToInts(data, start, dk, 0, len); 
			return new AutoKeyState(ep, dp, ek, dk);
		}

		public AutoKeyState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int ep = stream.readInt();
			int dp = stream.readInt();
			int[] ek = stream.readIntArr();
			int[] dk = stream.readInts(ek.length);
			return new AutoKeyState(ep, dp, ek, dk);
		}
		
	}

}
