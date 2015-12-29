package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.standards.ISecret;
import claire.util.crypto.rng.RandUtils;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class SubstitutionKey 
	   implements ISecret<SubstitutionKey> {
	
	private char[] key;
	private char[] inv;
	private char[] alphabet;
	
	public SubstitutionKey(char[] key, char[] alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = getInv(key, alphabet);
	}
	
	protected SubstitutionKey(char[] key, char[] inv, char[] alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = inv;
	}
	
	char[] getKey()
	{
		return this.key;
	}
	
	char[] getInv()
	{
		return this.inv;
	}

	public char[] getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		Arrays.fill(key, (char) 0);
		Arrays.fill(inv, (char) 0);
		key = null;
		inv = null;
		alphabet = null;
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeCharArr(key);
		stream.writeCharArr(inv);
		stream.writeCharArr(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		offset = IOUtils.writeArr(key, bytes, offset);
		offset = IOUtils.writeArr(inv, bytes, offset);
		IOUtils.writeArr(alphabet, bytes, offset);
	}
	
	public int exportSize()
	{
		return alphabet.length * 6 + 12;
	}

	public Factory<SubstitutionKey> factory()
	{
		return factory;
	}
	
	private static final Factory<SubstitutionKey> factory = new SubstitutionKeyFactory();
	
	private static final class SubstitutionKeyFactory extends Factory<SubstitutionKey>
	{

		protected SubstitutionKeyFactory()
		{
			super(SubstitutionKey.class);
		}

		public SubstitutionKey resurrect(byte[] data, int start) throws InstantiationException
		{
			
			char[] key = IOUtils.readCharArr(data, start);
			int size = key.length * 2 + 4;
			start += size;
			char[] inv = IOUtils.readCharArr(data, start);
			start += size;
			char[] alphabet = IOUtils.readCharArr(data, start);
			return new SubstitutionKey(key, inv, alphabet);
		}

		public SubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] key = stream.readCharArr();
			char[] inv = stream.readCharArr();
			char[] alphabet = stream.readCharArr();
			return new SubstitutionKey(key, inv, alphabet);
		}
		
	}
	
	public static final char[] getInv(final char[] key, final char[] alphabet)
	{
		char[] inv = new char[key.length];
		for(int i = 0; i < key.length; i++) {
			for(int j = 0; j < key.length; j++)
				if(alphabet[i] == key[j]) {
					inv[i] = alphabet[j];
					break;
				}
		}
		return inv;
	}
	
	public static final SubstitutionKey random(char[] alphabet, IRandom rng)
	{
		char[] key = ArrayUtil.copy(alphabet);
		RandUtils.randomize(key, rng);
		char[] inv = getInv(key, alphabet);
		return new SubstitutionKey(key, inv, alphabet);
	}

}
