package claire.simplecrypt.test;

import claire.simplecrypt.coders.SimpleCoder;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.util.logging.Log;
import claire.util.memory.util.ArrayUtil;

final class CipherTest {
	
	private static final SimpleCoder coder = new SimpleCoder(Test.ciphers[0], 1000);
	
	public static final int runTest()
	{
		Log.info.println();
		Log.info.println("----------------------------------");
		Log.info.println("Testing cipher properties");
		int fails = 0;
		for(int i = 0; i < Test.ciphers.length; i++)
		{
			ICipher<?, IState<?>> cip = Test.ciphers[i];
			coder.setCipher(cip);
			Log.info.println("Testing " + cip.getClass().getSimpleName());
			try {
				char[] plain = new char[81];
				char[] ab = cip.getKey().getAlphabet().getChars();
				if(cip.getKey().getAlphabet().getID() != Alphabet.ADVANCED.getID()) {
					fails++;
					Log.err.println("Cipher key did not report correct alphabet.");
				}
				for(int j = 0; j < 81; j++) 
					plain[j] = ab[Test.rng.nextIntFast(ab.length)];
				final int size = cip.ciphertextSize(61);
				char[] s1 = new char[size + 20];
				System.arraycopy(plain, 0, s1, 0, plain.length);
				char[] s2 = new char[s1.length];
				coder.encode(s1, 20, 61);
				cip.reset();
				coder.encode(plain, 20, s2, 20, 61);
				for(int j = 20; j < s1.length; j++) {
					if(s1[j] != s2[j]) {
						fails++;
						Log.err.println("In-Place enciphering gives different results then copy enciphering for " + cip.getClass().getSimpleName());
						Log.err.println(s1);
						Log.err.println(s2);
						break;
					}
				}
				char[] s3 = new char[s1.length];
				coder.decode(s1, 20, size);
				cip.reset();
				coder.decode(s2, 20, s3, 20, size);
				for(int j = 20; j < 81; j++) {
					if(s1[j] != s3[j]) {
						fails++;
						Log.err.println("In-Place deciphering gives different results then copy enciphering for " + cip.getClass().getSimpleName());
						Log.err.println(s1);
						Log.err.println(s3);
						break;
					}
				}
				for(int j = 20; j < 81; j++) {
					if((s1[j] & s3[j]) != plain[j]) {
						fails++;
						Log.err.println("One or both deciphering methods did not return the original plaintext for " + cip.getClass().getSimpleName());
						Log.err.println(plain);
						Log.err.println(s1);
						Log.err.println(s3);
						break;
					}
				}
				if(cip.hasState()) {
					cip.reset();
					coder.encode(s1);
					IState<?> state = cip.getState();
					System.arraycopy(plain, 0, s1, 0, 81);
					System.arraycopy(plain, 0, s2, 0, 81);
					System.arraycopy(plain, 0, s3, 0, 81);
					coder.encode(s1);
					cip.loadState(state);
					coder.encode(s2);
					if(!ArrayUtil.equals(s1, s2)) {
						Log.err.println("Loading state did not work");
						fails++;
						continue;
					}
					cip.updateState(state);
					coder.encode(s3);
					cip.loadState(state);
					System.arraycopy(plain, 0, s2, 0, 81);
					coder.encode(s2);
					if(!ArrayUtil.equals(s2, s3)) {
						Log.err.println("Updating the state did not work");
						fails++;
						continue;
					}
				}
			} catch(Exception e) {
				fails++;
				Log.err.println("Encountered unexpexted exception while testing " + cip.getClass().getSimpleName());
				Log.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
			}
		}
		return fails;
	}

}
