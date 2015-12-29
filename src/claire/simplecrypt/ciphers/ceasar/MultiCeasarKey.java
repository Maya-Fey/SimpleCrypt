package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.standards.ISecret;
import claire.util.crypto.rng.RandUtils;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiCeasarKey
	   implements ISecret<MultiCeasarKey> {

	private char[] alphabet;
	private int[] key;
	
	public MultiCeasarKey(char[] alphabet, String key)
	{
		this.alphabet = alphabet;
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
	
	public MultiCeasarKey(char[] alphabet, int[] key)
	{
		this.alphabet = alphabet;
		this.key = key;
	}
	
	int[] getKey()
	{
		return this.key;
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
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.length, bytes, offset); offset += 4;
		Bits.charsToBytes(alphabet, 0, bytes, offset); offset += alphabet.length * 2;
		Bits.intToBytes(key.length, bytes, offset); offset += 4; 
		Bits.intsToBytes(key, 0, bytes, offset); 
	}

	public int exportSize()
	{
		return 8 + (alphabet.length * 2) + (key.length * 4);
	}

	public Factory<MultiCeasarKey> factory()
	{
		return factory;
	}
	
	public static MultiCeasarKey random(char[] alphabet, int size, IRandom rand)
	{
		int[] arr = new int[size];
		RandUtils.fillArr(arr, rand);
		return new MultiCeasarKey(alphabet, arr);
	}
	
	private static final MultiCeasarKeyFactory factory = new MultiCeasarKeyFactory();
	
	private static final class MultiCeasarKeyFactory extends Factory<MultiCeasarKey>
	{

		protected MultiCeasarKeyFactory() 
		{
			super(MultiCeasarKey.class);
		}

		public MultiCeasarKey resurrect(byte[] data, int start) throws InstantiationException
		{
			char[] ab = new char[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToChars(data, start, ab, 0); start += ab.length * 2;
			int[] key = new int[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToInts(data, start, key, 0);
			return new MultiCeasarKey(ab, key);
		}
		
		public MultiCeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] ab = new char[stream.readInt()];
			stream.readChars(ab);
			int[] key = new int[stream.readInt()];
			stream.readInts(key);
			return new MultiCeasarKey(ab, key);
		}
		
	}

}
