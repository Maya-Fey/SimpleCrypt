package claire.simplecrypt.test;

import claire.simplecrypt.standards.ICipher;
import claire.util.logging.Log;
import claire.util.memory.util.ArrayUtil;

final class CipherTest {
	
	public static final int runTest()
	{
		Log.info.println();
		Log.info.println("----------------------------------");
		Log.info.println("Testing cipher properties");
		int fails = 0;
		for(int i = 0; i < Test.ciphers.length; i++)
		{
			ICipher<?> cip = Test.ciphers[i];
			Log.info.println("Testing " + cip.getClass().getSimpleName());
			try {
				char[] plain = new char[80];
				char[] ab = cip.getKey().getAlphabet();
				for(int j = 0; j < 80; j++) 
					plain[j] = ab[Test.rng.nextIntFast(ab.length)];
				
				char[] s1 = ArrayUtil.copy(plain);
				char[] s2 = new char[80];
				cip.encipher(s1, 20, 60);
				cip.reset();
				cip.encipher(plain, 20, s2, 20, 60);
				for(int j = 20; j < 80; j++) {
					if(s1[j] != s2[j]) {
						fails++;
						Log.err.println("In-Place enciphering gives different results then copy enciphering for " + cip.getClass().getSimpleName());
						Log.err.println(s1);
						Log.err.println(s2);
						break;
					}
				}
				char[] s3 = new char[80];
				cip.decipher(s1, 20, 60);
				cip.reset();
				cip.decipher(s2, 20, s3, 20, 60);
				for(int j = 20; j < 80; j++) {
					if(s1[j] != s3[j]) {
						fails++;
						Log.err.println("In-Place deciphering gives different results then copy enciphering for " + cip.getClass().getSimpleName());
						Log.err.println(s1);
						Log.err.println(s3);
						break;
					}
				}
				for(int j = 20; j < 80; j++) {
					if((s1[j] & s3[j]) != plain[j]) {
						fails++;
						Log.err.println("One or both deciphering methods did not return the original plaintext for " + cip.getClass().getSimpleName());
						Log.err.println(plain);
						Log.err.println(s1);
						Log.err.println(s3);
						break;
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
