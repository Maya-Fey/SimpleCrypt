package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IteratorCeasarKey
	   implements ISecret<IteratorCeasarKey> {

	private Alphabet alphabet;
	private int key;
	private int iterator;
	
	public IteratorCeasarKey(Alphabet alphabet, int key, int iterator)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.iterator = iterator;
	}
	
	int getKey()
	{
		return this.key;
	}
	
	int getIterator()
	{
		return this.iterator;
	}
	
	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		this.alphabet = null;
		this.key = 0;
		this.iterator = 0;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeInt(key);
		stream.writeInt(iterator);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.getID(), bytes, offset); offset += 4;
		Bits.intToBytes(key, bytes, offset); offset += 4;
		Bits.intToBytes(iterator, bytes, offset);
	}

	public int exportSize()
	{
		return 12;
	}

	public Factory<IteratorCeasarKey> factory()
	{
		return factory;
	}
	
	public static IteratorCeasarKey random(Alphabet alphabet, IRandom rand)
	{
		return new IteratorCeasarKey(alphabet, 1 + rand.nextIntGood(alphabet.getLen() - 1), 1 + rand.nextIntGood(alphabet.getLen() - 1));
	}
	
	private static final CeasarKeyFactory factory = new CeasarKeyFactory();
	
	private static final class CeasarKeyFactory extends Factory<IteratorCeasarKey>
	{

		protected CeasarKeyFactory() 
		{
			super(IteratorCeasarKey.class);
		}

		public IteratorCeasarKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int key = Bits.intFromBytes(data, start); start += 4;
			return new IteratorCeasarKey(alphabet, key, Bits.intFromBytes(data, start));
		}
		
		public IteratorCeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new IteratorCeasarKey(stream.resurrect(Alphabet.factory), stream.readInt(), stream.readInt());
		}
		
	}

}
