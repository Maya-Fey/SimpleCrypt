package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
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
	private Alphabet alphabet;
	
	public SubstitutionKey(char[] key, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
	}
	
	char[] getKey()
	{
		return this.key;
	}
	
	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		Arrays.fill(key, (char) 0);
		key = null;
		alphabet = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.SUBSTITUTIONKEY;
	}
	
	public boolean sameAs(SubstitutionKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && ArrayUtil.equals(this.key, obj.key);
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeCharArr(key);
		stream.persist(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		offset = IOUtils.writeArr(key, bytes, offset);
		alphabet.export(bytes, offset);
	}
	
	public int exportSize()
	{
		return alphabet.getLen() * 2 + 12;
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
			start += key.length * 2 + 4;
			Alphabet alphabet = Alphabet.factory.resurrect(data, start);
			return new SubstitutionKey(key, alphabet);
		}

		public SubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] key = stream.readCharArr();
			Alphabet alphabet = stream.resurrect(Alphabet.factory);
			return new SubstitutionKey(key, alphabet);
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
	
	public static final SubstitutionKey random(Alphabet alphabet, IRandom rng)
	{
		char[] key = ArrayUtil.copy(alphabet.getChars());
		RandUtils.randomize(key, rng);
		return new SubstitutionKey(key, alphabet);
	}

}
