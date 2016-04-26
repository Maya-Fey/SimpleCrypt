package claire.simplecrypt.ciphers.fraction;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.KeyFactory;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IPersistable;
import claire.util.standards.crypto.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiPolybiusKey 
	   implements ISecret<MultiPolybiusKey> {
	
	private Alphabet a;
	private byte[][] s1;
	private byte[][] s2;

	public MultiPolybiusKey(Alphabet a, final byte[][] s1, final byte[][] s2) 
	{
		this.s1 = s1;
		this.s2 = s2;
		this.a = a;
	}
	
	public Alphabet getAlphabet()
	{
		return a;
	}
	
	public byte[][] getSet1()
	{
		return this.s1;
	}
	
	public byte[][] getSet2()
	{
		return this.s2;
	}
	
	public void destroy()
	{
		for(int i = 0; i < s1.length; i++) {
			Arrays.fill(s1[i], (byte) 0);
			s1[i] = null;
		}
		for(int i = 0; i < s2.length; i++) {
			Arrays.fill(s1[i], (byte) 0);
			s1[i] = null;
		}
		s1 = null;
		s2 = null;
		a = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.POLYBIUSKEY;
	}

	public boolean sameAs(MultiPolybiusKey obj)
	{
		if(a.getLen() == obj.a.getLen() && (s1.length == obj.s1.length && s2.length == obj.s2.length)) {
			byte[][] ob = obj.s1;
			for(int i = 0; i < s1.length; i++)
				if(!ArrayUtil.equals(ob[i], s1[i]))
					return false;
			ob = obj.s2;
			for(int i = 0; i < s2.length; i++)
				if(!ArrayUtil.equals(ob[i], s2[i]))
					return false;
			return true;
		}
		return false;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(a);
		stream.writeInt(s1.length);
		stream.writeInt(s1[0].length);
		stream.writeInt(s2[1].length);
		for(byte[] b : s1)
			stream.writeBytes(b);
		for(byte[] b : s2)
			stream.writeBytes(b);
	}

	public void export(byte[] bytes, int offset)
	{
		a.export(bytes, offset); offset += 4;
		Bits.intToBytes(s1.length, bytes, offset); offset += 4;
		Bits.intToBytes(s1[0].length, bytes, offset); offset += 4;
		Bits.intToBytes(s2[0].length, bytes, offset); offset += 4;
		for(byte[] b : s1)
			offset = IPersistable.persistBytes(b, bytes, offset);
		for(byte[] b : s2)
			offset = IPersistable.persistBytes(b, bytes, offset);
	}

	public int exportSize()
	{
		return (s1.length * s1[0].length) + (s2.length * s2[0].length) + 16;
	}

	public Factory<MultiPolybiusKey> factory()
	{
		return factory;
	}
	
	public static final PolybiusKeyFactory factory = new PolybiusKeyFactory();
	
	private static final class PolybiusKeyFactory extends KeyFactory<MultiPolybiusKey> {

		protected PolybiusKeyFactory() 
		{
			super(MultiPolybiusKey.class);
		}

		public MultiPolybiusKey resurrect(final byte[] data, int start) throws InstantiationException
		{
			final Alphabet a = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			final int len = Bits.intFromBytes(data, start); start += 4;
			final int s1l = Bits.intFromBytes(data, start); start += 4;
			final int s2l = Bits.intFromBytes(data, start); start += 4;
			final byte[][] s1 = new byte[len][s1l];
			final byte[][] s2 = new byte[len][s2l];
			for(int i = 0; i < len; i++) 
				start = IPersistable.readBytes(s1[i], data, start);
			for(int i = 0; i < len; i++) 
				start = IPersistable.readBytes(s2[i], data, start);
			return new MultiPolybiusKey(a, s1, s2);
		}

		public MultiPolybiusKey resurrect(final IIncomingStream stream) throws InstantiationException, IOException
		{
			final Alphabet ab = stream.resurrect(Alphabet.factory);
			final int len = stream.readInt();
			final int s1l = stream.readInt();
			final int s2l = stream.readInt();
			final byte[][] s1 = new byte[len][s1l];
			final byte[][] s2 = new byte[len][s2l];
			for(int i = 0; i < len; i++)
				stream.readBytes(s1[i]);
			for(int i = 0; i < len; i++)
				stream.readBytes(s2[i]);
			return new MultiPolybiusKey(ab, s1, s2);
		}

		public MultiPolybiusKey random(final Alphabet ab, final IRandom<?> rand)
		{
			final int len = 1 + rand.nextIntFast(8);
			final byte[][] rowt = new byte[len][PolybiusKey.ROWLEN[ab.getID()]];
			final byte[][] colt = new byte[len][PolybiusKey.COLLEN[ab.getID()]];
			int k = 0;
			while(k < len)
			{
				final byte[] row = rowt[k  ];
				final byte[] col = colt[k++];
				row[0] = (byte) rand.nextIntFast(row.length);
				col[0] = (byte) rand.nextIntFast(row.length);
				for(int i = 1; i < row.length; i++) {
					byte b = (byte) rand.nextIntFast(ab.getLen());
					for(int j = 0; j < i; j++)
						if(row[j] == b) {
							j = 0;
							b = (byte) rand.nextIntFast(ab.getLen());
						}
					row[i] = b;
				}
				for(int i = 1; i < col.length; i++) {
					byte b = (byte) rand.nextIntFast(ab.getLen());
					for(int j = 0; j < i; j++)
						if(col[j] == b) {
							j = 0;
							b = (byte) rand.nextIntFast(ab.getLen());
						}
					col[i] = b;
				}
			}
			return new MultiPolybiusKey(ab, rowt, colt);
		}
		
	}
	
	public static final MultiPolybiusKey random(final Alphabet ab, int len, final IRandom<?> rand)
	{
		final byte[][] rowt = new byte[len][PolybiusKey.ROWLEN[ab.getID()]];
		final byte[][] colt = new byte[len][PolybiusKey.COLLEN[ab.getID()]];
		int k = 0;
		while(k < len)
		{
			final byte[] row = rowt[k  ];
			final byte[] col = colt[k++];
			row[0] = (byte) rand.nextIntFast(row.length);
			col[0] = (byte) rand.nextIntFast(row.length);
			for(int i = 1; i < row.length; i++) {
				byte b = (byte) rand.nextIntFast(ab.getLen());
				for(int j = 0; j < i; j++)
					if(row[j] == b) {
						j = 0;
						b = (byte) rand.nextIntFast(ab.getLen());
					}
				row[i] = b;
			}
			for(int i = 1; i < col.length; i++) {
				byte b = (byte) rand.nextIntFast(ab.getLen());
				for(int j = 0; j < i; j++)
					if(col[j] == b) {
						j = 0;
						b = (byte) rand.nextIntFast(ab.getLen());
					}
				col[i] = b;
			}
		}
		return new MultiPolybiusKey(ab, rowt, colt);
	}

}
