package claire.simplecrypt.ciphers.mathematical;

import java.io.IOException;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.math.MathHelper;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IteratorAffineKey
	   implements ISecret<IteratorAffineKey> {

	private Alphabet alphabet;
	private int iterator;
	private int key;
	private int mul;
	private int inv;
	
	public IteratorAffineKey(Alphabet alphabet, int key, int iterator, int mul, int inv)
	{
		this.alphabet = alphabet;
		this.iterator = iterator;
		this.key = key;
		this.mul = mul;
		this.inv = inv;
	}
	
	int getMul()
	{
		return this.mul;
	}
	
	int getInv()
	{
		return this.inv;
	}
	
	int getAdd()
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
		this.mul = 0;
		this.inv = 0;
		this.iterator = 0;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.ITERATORAFFINEKEY;
	}

	public boolean sameAs(IteratorAffineKey obj)
	{
		return (this.alphabet.getID() == obj.alphabet.getID() && this.iterator == obj.iterator) && (this.mul == obj.mul && this.key == obj.key);
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeInt(key);
		stream.writeInt(iterator);
		stream.writeInt(mul);
		stream.writeInt(inv);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		Bits.intToBytes(key, bytes, offset); offset += 4;
		Bits.intToBytes(iterator, bytes, offset); offset += 4;
		Bits.intToBytes(mul, bytes, offset); offset += 4;
		Bits.intToBytes(inv, bytes, offset);
	}

	public int exportSize()
	{
		return 20;
	}

	public Factory<IteratorAffineKey> factory()
	{
		return factory;
	}
	
	public static IteratorAffineKey random(Alphabet alphabet, IRandom rand)
	{
		final int mod = alphabet.getLen();
		int mul;
		int inv;
		while(true) {
			mul = 1 + rand.nextIntGood(alphabet.getLen() - 1);
			if(MathHelper.gcd(mul, mod) == 1) {
				inv = MathHelper.modular_inverse(mul, mod);
				break;
			}
		}
		return new IteratorAffineKey(alphabet, 1 + rand.nextIntGood(alphabet.getLen() - 1),  + rand.nextIntGood(alphabet.getLen() - 1), mul, inv);
	}
	
	private static final AffineKeyFactory factory = new AffineKeyFactory();
	
	private static final class AffineKeyFactory extends Factory<IteratorAffineKey>
	{

		protected AffineKeyFactory() 
		{
			super(IteratorAffineKey.class);
		}

		public IteratorAffineKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int add = Bits.intFromBytes(data, start); start += 4;
			int iterator = Bits.intFromBytes(data, start); start += 4;
			int mul = Bits.intFromBytes(data, start); start += 4;
			return new IteratorAffineKey(alphabet, add, iterator, mul, Bits.intFromBytes(data, start));
		}
		
		public IteratorAffineKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new IteratorAffineKey(stream.resurrect(Alphabet.factory), stream.readInt(), stream.readInt(), stream.readInt(), stream.readInt());
		}
		
	}

}
