package claire.simplecrypt.ciphers.feistel;

import java.io.IOException;

import claire.simplecrypt.ciphers.feistel.IterativeFeistel.IterativeFeistelState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IterativeFeistel
	   implements ICipher<FeistelKey, IterativeFeistelState> {
	
	private FeistelKey mkey;
	private Alphabet ab;
	private byte[] key;
	
	private int epos = 0;
	private int dpos = -1;
	
	public IterativeFeistel(FeistelKey key)
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
				plaintext[start] = (byte) ((plaintext[start] + plaintext[start + 1] + key[i] + epos++) % ab.getLen());
				if(epos == ab.getLen())
					epos = 0;
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
					plaintext[start] = (byte) ((plaintext[start] + plaintext[start + 1] + key[i] + epos++) % ab.getLen());
				else
					plaintext[start] = (byte) ((plaintext[start] + key[i]) % ab.getLen());
				if(epos == ab.getLen())
					epos = 0;
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
			int tpos = dpos += key.length;
			if(dpos >= ab.getLen())
				dpos -= ab.getLen();
			for(int i = key.length; i > 0;)
			{
				ciphertext[base] = (byte) (ciphertext[base] - ((ciphertext[start] + key[--i] + tpos--) % ab.getLen()));
				if(tpos < 0)
					tpos += ab.getLen();
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
			int tpos = dpos += len;
			if(dpos >= ab.getLen())
				dpos -= ab.getLen();
			for(int i = len; i > 0;)
			{
				if(len > 1)
					ciphertext[base] = (byte) (ciphertext[base] - ((ciphertext[start] + key[--i] + tpos--) % ab.getLen()));
				else
					ciphertext[base] = (byte) (ciphertext[base] - key[--i]);
				if(tpos < 0)
					tpos += ab.getLen();
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
		epos = 0;
		dpos = -1;
	}

	public void reset() 
	{
		epos = 0;
		dpos = -1;
	}
	
	public IterativeFeistelState getState() 
	{ 
		return new IterativeFeistelState(this); 
	}
	
	public void loadState(IterativeFeistelState state) 
	{
		this.epos = state.epos;
		this.dpos = state.dpos;
	}
	
	public void updateState(IterativeFeistelState state) 
	{
		state.epos = this.epos;
		state.dpos = this.dpos;
	}
	
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
	
	public static final IterativeFeistelStateFactory sfactory = new IterativeFeistelStateFactory();
	
	public static final class IterativeFeistelState implements IState<IterativeFeistelState>
	{
		private int epos;
		private int dpos;
		
		public IterativeFeistelState(IterativeFeistel c)
		{
			epos = c.epos;
			dpos = c.dpos;
		}
		
		public IterativeFeistelState(int e, int d)
		{
			this.epos = e;
			this.dpos = d;
		}

		public int NAMESPACE()
		{
			return NamespaceKey.ITERATIVEFEISTELSTATE;
		}
		
		public boolean sameAs(IterativeFeistelState obj)
		{
			return epos == obj.epos && dpos == obj.dpos;
		}
		
		public void export(IOutgoingStream stream) throws IOException
		{
			stream.writeInt(epos);
			stream.writeInt(dpos);
		}

		public void export(byte[] bytes, int offset)
		{
			Bits.intToBytes(epos, bytes, offset); offset += 4;
			Bits.intToBytes(dpos, bytes, offset);
		}

		public int exportSize()
		{
			return 8;
		}

		public Factory<IterativeFeistelState> factory()
		{
			return sfactory;
		}
		
	}
	
	private static final class IterativeFeistelStateFactory extends Factory<IterativeFeistelState>
	{

		protected IterativeFeistelStateFactory() 
		{
			super(IterativeFeistelState.class);
		}

		public IterativeFeistelState resurrect(byte[] data, int start) throws InstantiationException
		{
			int e = Bits.intFromBytes(data, start); start += 4;
			return new IterativeFeistelState(e, Bits.intFromBytes(data, start));
		}

		public IterativeFeistelState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new IterativeFeistelState(stream.readInt(), stream.readInt());
		}
		
	}
	
}
