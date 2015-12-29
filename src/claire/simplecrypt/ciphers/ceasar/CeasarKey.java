package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;

import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class CeasarKey
	   implements ISecret<CeasarKey> {

	private char[] alphabet;
	private int key;
	
	public CeasarKey(char[] alphabet, int key)
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
		return this.alphabet;
	}

	public void destroy()
	{
		this.alphabet = null;
		this.key = 0;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(alphabet.length);
		stream.writeChars(alphabet);
		stream.writeInt(key);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.length, bytes, offset); offset += 4;
		Bits.charsToBytes(alphabet, 0, bytes, offset); offset += alphabet.length * 2;
		Bits.intToBytes(key, bytes, offset); 
	}

	public int exportSize()
	{
		return 8 + (alphabet.length * 2);
	}

	public Factory<CeasarKey> factory()
	{
		return factory;
	}
	
	public static CeasarKey random(char[] alphabet, IRandom rand)
	{
		return new CeasarKey(alphabet, 1 + rand.nextIntGood(alphabet.length - 1));
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
			char[] ab = new char[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToChars(data, start, ab, 0); start += ab.length * 2;
			return new CeasarKey(ab, Bits.intFromBytes(data, start));
		}
		
		public CeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] ab = new char[stream.readInt()];
			stream.readChars(ab);
			return new CeasarKey(ab, stream.readInt());
		}
		
	}

}
