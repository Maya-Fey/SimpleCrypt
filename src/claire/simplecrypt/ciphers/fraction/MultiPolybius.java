package claire.simplecrypt.ciphers.fraction;

import java.io.IOException;

import claire.simplecrypt.ciphers.fraction.MultiPolybius.MultiPolybiusState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiPolybius 
	   implements ICipher<MultiPolybiusKey, MultiPolybiusState> {

	private MultiPolybiusKey key;
	private Alphabet ab;
	
	private byte[][] row;
	private byte[][] col;
	
	private int epos = 0;
	private int dpos = 0;
	
	private byte[] buffer;
	
	public MultiPolybius(MultiPolybiusKey key) 
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
			final byte[] col = this.col[epos  ];
			final byte[] row = this.row[epos++];
			if(epos == this.row.length)
				epos = 0;
			plaintext[start++] = col[buffer[i  ] / row.length];
			plaintext[start++] = row[buffer[i++] % row.length];
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			final byte[] col = this.col[epos  ];
			final byte[] row = this.row[epos++];
			if(epos == this.row.length)
				epos = 0;
			ciphertext[start1++] = col[plaintext[start0  ] / row.length];
			ciphertext[start1++] = row[plaintext[start0++] % row.length];
		}
	}
	
	public void decipher(byte[] ciphertext, int start, int len)
	{
		int pos = start;
		while(len > 0) {
			final byte[] col = this.col[dpos  ];
			final byte[] row = this.row[dpos++];
			if(dpos == this.row.length)
				dpos = 0;
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
			final byte[] col = this.col[dpos  ];
			final byte[] row = this.row[dpos++];
			if(dpos == this.row.length)
				dpos = 0;
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

	public void reset() 
	{
		epos = dpos = 0;
	}

	public void destroy()
	{
		this.ab = null;
		this.key = null;
		this.row = this.col = null;
		epos = dpos = 0;
	}

	public void loadState(MultiPolybiusState state) 
	{
		this.epos = state.epos;
		this.dpos = state.dpos;
	}
	
	public void updateState(MultiPolybiusState state) 
	{
		state.epos = this.epos;
		state.dpos = this.dpos;
	}
	
	public MultiPolybiusKey getKey()
	{
		return this.key;
	}
	
	public void setKey(MultiPolybiusKey key)
	{
		this.row = key.getSet1();
		this.col = key.getSet2();
		this.key = key;
		this.ab = key.getAlphabet();
	}
	
	public MultiPolybiusState getState()
	{
		return new MultiPolybiusState(this);
	}

	public boolean hasState()
	{
		return true;
	}

	public Alphabet getAlphabet()
	{
		return this.ab;
	}
	
	public static final MultiPolybiusStateFactory sfactory = new MultiPolybiusStateFactory();
	
	public static final class MultiPolybiusState implements IState<MultiPolybiusState>
	{
		private int epos;
		private int dpos;
		
		public MultiPolybiusState(MultiPolybius c)
		{
			epos = c.epos;
			dpos = c.dpos;
		}
		
		public MultiPolybiusState(int e, int d)
		{
			this.epos = e;
			this.dpos = d;
		}

		public int NAMESPACE()
		{
			return NamespaceKey.MULTICEASARSTATE;
		}
		
		public boolean sameAs(MultiPolybiusState obj)
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

		public Factory<MultiPolybiusState> factory()
		{
			return sfactory;
		}
		
	}
	
	private static final class MultiPolybiusStateFactory extends Factory<MultiPolybiusState>
	{

		protected MultiPolybiusStateFactory() 
		{
			super(MultiPolybiusState.class);
		}

		public MultiPolybiusState resurrect(byte[] data, int start) throws InstantiationException
		{
			int e = Bits.intFromBytes(data, start); start += 4;
			return new MultiPolybiusState(e, Bits.intFromBytes(data, start));
		}

		public MultiPolybiusState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new MultiPolybiusState(stream.readInt(), stream.readInt());
		}
		
	}
	
}
