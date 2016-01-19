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

public class AffineKey
	   implements ISecret<AffineKey> {

	private Alphabet alphabet;
	private int key;
	private int mul;
	private int inv;
	
	public AffineKey(Alphabet alphabet, int key, int mul, int inv)
	{
		this.alphabet = alphabet;
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
	
	public Alphabet getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		this.alphabet = null;
		this.key = 0;
		this.mul = 0;
		this.inv = 0;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.AFFINEKEY;
	}

	public boolean sameAs(AffineKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && (this.mul == obj.mul && this.key == obj.key);
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeInt(key);
		stream.writeInt(mul);
		stream.writeInt(inv);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		Bits.intToBytes(key, bytes, offset); offset += 4;
		Bits.intToBytes(mul, bytes, offset); offset += 4;
		Bits.intToBytes(inv, bytes, offset);
	}

	public int exportSize()
	{
		return 16;
	}

	public Factory<AffineKey> factory()
	{
		return factory;
	}
	
	public static AffineKey random(Alphabet alphabet, IRandom rand)
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
		return new AffineKey(alphabet, 1 + rand.nextIntGood(alphabet.getLen() - 1), mul, inv);
	}
	
	public static final AffineKeyFactory factory = new AffineKeyFactory();
	
	private static final class AffineKeyFactory extends Factory<AffineKey>
	{

		protected AffineKeyFactory() 
		{
			super(AffineKey.class);
		}

		public AffineKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int add = Bits.intFromBytes(data, start); start += 4;
			int mul = Bits.intFromBytes(data, start); start += 4;
			return new AffineKey(alphabet, add, mul, Bits.intFromBytes(data, start));
		}
		
		public AffineKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new AffineKey(stream.resurrect(Alphabet.factory), stream.readInt(), stream.readInt(), stream.readInt());
		}
		
	}

}
