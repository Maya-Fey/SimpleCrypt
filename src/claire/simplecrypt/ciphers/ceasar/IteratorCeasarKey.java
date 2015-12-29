package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;

import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IteratorCeasarKey
	   implements ISecret<IteratorCeasarKey> {

	private char[] alphabet;
	private int key;
	private int iterator;
	
	public IteratorCeasarKey(char[] alphabet, int key, int iterator)
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
		return this.alphabet;
	}

	public void destroy()
	{
		this.alphabet = null;
		this.key = 0;
		this.iterator = 0;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(alphabet.length);
		stream.writeChars(alphabet);
		stream.writeInt(key);
		stream.writeInt(iterator);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.length, bytes, offset); offset += 4;
		Bits.charsToBytes(alphabet, 0, bytes, offset); offset += alphabet.length * 2;
		Bits.intToBytes(key, bytes, offset); offset += 4;
		Bits.intToBytes(iterator, bytes, offset);
	}

	public int exportSize()
	{
		return 8 + (alphabet.length * 2);
	}

	public Factory<IteratorCeasarKey> factory()
	{
		return factory;
	}
	
	public static IteratorCeasarKey random(char[] alphabet, IRandom rand)
	{
		return new IteratorCeasarKey(alphabet, 1 + rand.nextIntGood(alphabet.length - 1), 1 + rand.nextIntGood(alphabet.length - 1));
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
			char[] ab = new char[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToChars(data, start, ab, 0); start += ab.length * 2;
			int key = Bits.intFromBytes(data, start); start += 4;
			return new IteratorCeasarKey(ab, key, Bits.intFromBytes(data, start));
		}
		
		public IteratorCeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] ab = new char[stream.readInt()];
			stream.readChars(ab);
			return new IteratorCeasarKey(ab, stream.readInt(), stream.readInt());
		}
		
	}

}
