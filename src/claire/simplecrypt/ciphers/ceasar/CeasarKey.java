package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class CeasarKey
	   implements ISecret<CeasarKey> {

	private Alphabet alphabet;
	private int key;
	
	public CeasarKey(Alphabet alphabet, int key)
	{
		this.alphabet = alphabet;
		this.key = key;
	}
	
	int getKey()
	{
		return this.key;
	}
	
	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		this.alphabet = null;
		this.key = 0;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeInt(key);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		Bits.intToBytes(key, bytes, offset); 
	}

	public int exportSize()
	{
		return 8;
	}

	public Factory<CeasarKey> factory()
	{
		return factory;
	}
	
	public static CeasarKey random(Alphabet alphabet, IRandom rand)
	{
		return new CeasarKey(alphabet, 1 + rand.nextIntGood(alphabet.getLen() - 1));
	}
	
	private static final CeasarKeyFactory factory = new CeasarKeyFactory();
	
	private static final class CeasarKeyFactory extends Factory<CeasarKey>
	{

		protected CeasarKeyFactory() 
		{
			super(CeasarKey.class);
		}

		public CeasarKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			return new CeasarKey(alphabet, Bits.intFromBytes(data, start));
		}
		
		public CeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new CeasarKey(stream.resurrect(Alphabet.factory), stream.readInt());
		}
		
	}

}
