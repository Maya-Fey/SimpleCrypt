package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.KeyFactory;
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
	
	private byte[] key;	
	private byte[] inv;
	private Alphabet alphabet;
	
	public SubstitutionKey(byte[] key, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = getInv(key);
	}
	
	public SubstitutionKey(byte[] key, byte[] inv, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = inv;
	}
	
	byte[] getKey()
	{
		return this.key;
	}
	
	byte[] getInv()
	{
		return this.inv;
	}
	
	public Alphabet getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		Arrays.fill(key, (byte) 0);
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
		stream.writeByteArr(key);
		stream.writeByteArr(inv);
		stream.persist(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		offset = IOUtils.writeArr(key, bytes, offset);
		offset = IOUtils.writeArr(inv, bytes, offset);
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
	
	public static final SubstitutionKeyFactory factory = new SubstitutionKeyFactory();
	
	private static final class SubstitutionKeyFactory extends KeyFactory<SubstitutionKey>
	{

		protected SubstitutionKeyFactory()
		{
			super(SubstitutionKey.class);
		}

		public SubstitutionKey resurrect(byte[] data, int start) throws InstantiationException
		{
			byte[] key = IOUtils.readByteArr(data, start);
			start += key.length + 4;
			byte[] inv = IOUtils.readByteArr(data, start);
			start += key.length + 4;
			Alphabet alphabet = Alphabet.factory.resurrect(data, start);
			return new SubstitutionKey(key, inv, alphabet);
		}

		public SubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			byte[] key = stream.readByteArr();
			byte[] inv = stream.readByteArr();
			Alphabet alphabet = stream.resurrect(Alphabet.factory);
			return new SubstitutionKey(key, inv, alphabet);
		}

		public SubstitutionKey random(Alphabet ab, IRandom rand)
		{
			return SubstitutionKey.random(ab, rand);
		}
		
	}
	
	public static final byte[] getInv(final byte[] key)
	{
		byte[] inv = new byte[key.length];
		for(int i = 0; i < key.length; i++) {
			inv[key[i]] = (byte) i;
		}
		return inv;
	}
	
	public static final SubstitutionKey random(Alphabet alphabet, IRandom rng)
	{
		byte[] key = new byte[alphabet.getLen()];
		for(int i = 0; i < key.length; i++)
			key[i] = (byte) i;
		RandUtils.randomize(key, rng);
		return new SubstitutionKey(key, alphabet);
	}
	
	public static final byte[] fromChars(Alphabet ab, char[] chars)
	{
		byte[] bytes = new byte[chars.length];
		for(int i = 0; i < ab.getLen(); i++)
			bytes[i] = ab.convertTo(chars[i]);
		return bytes;
	}
	
	public static final byte[] fromChars(Alphabet ab, char[] chars, byte[] bytes)
	{
		for(int i = 0; i < ab.getLen(); i++)
			bytes[i] = ab.convertTo(chars[i]);
		return bytes;
	}
	
	public static final byte[] fromChars(Alphabet ab, String s)
	{
		byte[] bytes = new byte[s.length()];
		for(int i = 0; i < ab.getLen(); i++)
			bytes[i] = ab.convertTo(s.charAt(i));
		return bytes;
	}
	
	public static final byte[] fromChars(Alphabet ab, String s, byte[] bytes)
	{
		for(int i = 0; i < ab.getLen(); i++)
			bytes[i] = ab.convertTo(s.charAt(i));
		return bytes;
	}

}
