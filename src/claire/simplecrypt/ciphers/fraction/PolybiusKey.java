package claire.simplecrypt.ciphers.fraction;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.KeyFactory;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.crypto.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class PolybiusKey 
	   implements ISecret<PolybiusKey> {
	
	static final int[] ROWLEN = new int[]
		{
			6, 6, 8, 6, 8, 7, 7, 8, 8, 9, 10
		};
	
	static final int[] COLLEN = new int[]
		{
			5, 5, 7, 5, 7, 6, 6, 8, 8, 9, 9
		};
	
	private Alphabet a;
	private byte[] s1;
	private byte[] s2;

	public PolybiusKey(Alphabet a, final byte[] s1, final byte[] s2) 
	{
		this.s1 = s1;
		this.s2 = s2;
		this.a = a;
	}
	
	public Alphabet getAlphabet()
	{
		return a;
	}
	
	public byte[] getSet1()
	{
		return this.s1;
	}
	
	public byte[] getSet2()
	{
		return this.s2;
	}
	
	public void destroy()
	{
		Arrays.fill(s2, (byte) 0);
		Arrays.fill(s1, (byte) 0);
		s1 = null;
		s2 = null;
		a = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.POLYBIUSKEY;
	}

	public boolean sameAs(PolybiusKey obj)
	{
		return a.getID() == obj.a.getID() && (ArrayUtil.equals(s1, obj.s1) && ArrayUtil.equals(s2, obj.s2));
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(a);
		stream.writeByteArr(s1);
		stream.writeByteArr(s2);
	}

	public void export(byte[] bytes, int offset)
	{
		a.export(bytes, offset); offset += 4;
		offset = IOUtils.writeArr(s1, bytes, offset);
		IOUtils.writeArr(s2, bytes, offset);
	}

	public int exportSize()
	{
		return s1.length + s2.length + 12;
	}

	public Factory<PolybiusKey> factory()
	{
		return factory;
	}
	
	public static final PolybiusKeyFactory factory = new PolybiusKeyFactory();
	
	private static final class PolybiusKeyFactory extends KeyFactory<PolybiusKey> {

		protected PolybiusKeyFactory() 
		{
			super(PolybiusKey.class);
		}

		public PolybiusKey resurrect(final byte[] data, int start) throws InstantiationException
		{
			final Alphabet a = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			final byte[] s1 = IOUtils.readByteArr(data, start); start += s1.length + 4;
			return new PolybiusKey(a, s1, IOUtils.readByteArr(data, start));
		}

		public PolybiusKey resurrect(final IIncomingStream stream) throws InstantiationException, IOException
		{
			return new PolybiusKey(Alphabet.fromID(stream.readInt()), stream.readByteArr(), stream.readByteArr());
		}

		public PolybiusKey random(final Alphabet ab, final IRandom<?, ?> rand)
		{
			final byte[] row = new byte[ROWLEN[ab.getID()]];
			final byte[] col = new byte[COLLEN[ab.getID()]];
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
			return new PolybiusKey(ab, row, col);
		}
		
	}
	
	public static final PolybiusKey random(final Alphabet ab, final IRandom<?, ?> rand)
	{
		final byte[] row = new byte[ROWLEN[ab.getID()]];
		final byte[] col = new byte[COLLEN[ab.getID()]];
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
		return new PolybiusKey(ab, row, col);
	}
	
	public static final int getRow(int ab)
	{
		return ROWLEN[ab];
	}
	
	public static final int getCol(int ab)
	{
		return COLLEN[ab];
	}

}
