package org.genericname.Ogham.crypto;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.jcajce.provider.digest.Blake2b;

public class Hash {
    private static Blake2b.Blake2b256 digest = new Blake2b.Blake2b256();

    public static byte[] blake2(byte[] in) {
        try {
            digest.reset();
            digest.update(in, 0, in.length);
            return digest.digest();
        } catch (Exception e) {
            System.out.println("Fatal Error: Hashing failed.");
            System.exit(-1);
            return null;
        }
    }


}
