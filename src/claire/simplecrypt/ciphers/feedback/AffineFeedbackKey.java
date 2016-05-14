package claire.simplecrypt.ciphers.feedback;

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

public class AffineFeedbackKey
	   implements ISecret<AffineFeedbackKey> {

	private Alphabet alphabet;
	private int[] key;
	private int[] mul;
	
	public AffineFeedbackKey(Alphabet alphabet, int[] key, int[] mul)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.mul = mul;
	}
	
	int[] getMul()
	{
		return this.mul;
	}
	
	int[] getAdd()
	{
		return this.key;
	}
	
	public Alphabet getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		this.alphabet = null;
		Arrays.fill(key, 0);
		Arrays.fill(mul, 0);
		this.key = null;
		this.mul = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.AFFINEFEEDBACKKEY;
	}

	public boolean sameAs(AffineFeedbackKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && (ArrayUtil.equals(this.key, obj.key) && ArrayUtil.equals(this.mul, obj.mul));
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeIntArr(key);
		stream.writeIntArr(mul);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		offset = IOUtils.writeArr(key, bytes, offset);
		IOUtils.writeArr(mul, bytes, offset);
	}

	public int exportSize()
	{
		return (8 * key.length) + 12;
	}

	public Factory<AffineFeedbackKey> factory()
	{
		return factory;
	}
	
	public static AffineFeedbackKey random(Alphabet alphabet, int size, IRandom<?, ?> rand)
	{
		final int mod = alphabet.getLen();
		final int max = mod - 1;
		int start = 0;
		int[] add = new int[size];
		int[] mul = new int[size];
		while(size-- > 0)
		{
			add[start] = rand.nextIntGood(max);
			mul[start++] = 1 + rand.nextIntGood(alphabet.getLen() - 1);
		}
		return new AffineFeedbackKey(alphabet, add, mul);
	}
	
	public static final AffineFeedbackKeyFactory factory = new AffineFeedbackKeyFactory();
	
	private static final class AffineFeedbackKeyFactory extends KeyFactory<AffineFeedbackKey>
	{

		protected AffineFeedbackKeyFactory() 
		{
			super(AffineFeedbackKey.class);
		}

		public AffineFeedbackKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int[] add = IOUtils.readIntArr(data, start);
			int size = add.length * 4 + 4; start += size;
			return new AffineFeedbackKey(alphabet, add, IOUtils.readIntArr(data, start));
		}
		
		public AffineFeedbackKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new AffineFeedbackKey(stream.resurrect(Alphabet.factory), stream.readIntArr(), stream.readIntArr());
		}

		public AffineFeedbackKey random(Alphabet ab, IRandom<?, ?> rand)
		{
			return AffineFeedbackKey.random(ab, 2 + rand.nextIntGood(7), rand);
		}
		
	}

}
