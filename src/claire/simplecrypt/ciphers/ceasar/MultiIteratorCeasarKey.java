package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiIteratorCeasarKey
	   implements ISecret<MultiIteratorCeasarKey> {

	private char[] alphabet;
	private int[] key;
	private int iterator;
	
	public MultiIteratorCeasarKey(char[] alphabet, String key, int iterator)
	{
		this.alphabet = alphabet;
		this.iterator = iterator;
		this.key = new int[key.length()];
		for(int i = 0; i < key.length(); i++) {
			char c = key.charAt(i);
			for(int j = 0; j <= alphabet.length; j++)
				if(c == alphabet[j]) {
					this.key[i] = j;
					break;
				}
		}
	}
	
	public MultiIteratorCeasarKey(char[] alphabet, int[] key, int iterator)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.iterator = iterator;
	}
	
	int[] getKey()
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
		Arrays.fill(key, 0);
		this.key = null;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(alphabet.length);
		stream.writeChars(alphabet);
		stream.writeInt(key.length);
		stream.writeInts(key);
		stream.writeInt(iterator);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.length, bytes, offset); offset += 4;
		Bits.charsToBytes(alphabet, 0, bytes, offset); offset += alphabet.length * 2;
		Bits.intToBytes(key.length, bytes, offset); offset += 4; 
		Bits.intsToBytes(key, 0, bytes, offset); offset += (key.length * 4);
		Bits.intToBytes(iterator, bytes, offset);
	}

	public int exportSize()
	{
		return 12 + (alphabet.length * 2) + (key.length * 4);
	}

	public Factory<MultiIteratorCeasarKey> factory()
	{
		return factory;
	}
	
	public static MultiIteratorCeasarKey random(char[] alphabet, int size, IRandom rand)
	{
		int[] arr = new int[size];
		for(int i = 0; i < size; i++)
			arr[i] = rand.nextIntFast(alphabet.length);
		return new MultiIteratorCeasarKey(alphabet, arr, 1 + rand.nextIntFast(alphabet.length - 1));
	}
	
	private static final MultiCeasarKeyFactory factory = new MultiCeasarKeyFactory();
	
	private static final class MultiCeasarKeyFactory extends Factory<MultiIteratorCeasarKey>
	{

		protected MultiCeasarKeyFactory() 
		{
			super(MultiIteratorCeasarKey.class);
		}

		public MultiIteratorCeasarKey resurrect(byte[] data, int start) throws InstantiationException
		{
			char[] ab = new char[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToChars(data, start, ab, 0); start += ab.length * 2;
			int[] key = new int[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToInts(data, start, key, 0); start += key.length * 4;
			return new MultiIteratorCeasarKey(ab, key, Bits.intFromBytes(data, start));
		}
		
		public MultiIteratorCeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] ab = new char[stream.readInt()];
			stream.readChars(ab);
			int[] key = new int[stream.readInt()];
			stream.readInts(key);
			return new MultiIteratorCeasarKey(ab, key, stream.readInt());
		}
		
	}

}
