package org.genericname.Ogham.crypto;

import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.math.ec.*;
import static org.genericname.Ogham.crypto.Hash.blake2;

public class Ed25519 {
    public static byte[] newKeypair() {
        SecureRandom rand = new SecureRandom();

        byte[] privKey = new byte[org.bouncycastle.math.ec.rfc8032.Ed25519.SECRET_KEY_SIZE];
        rand.nextBytes(privKey);

        return blake2(privKey);
    }

    public static byte[] calcPubkey(byte[] privKey) {
        byte[] pubKey = new byte[org.bouncycastle.math.ec.rfc8032.Ed25519.PUBLIC_KEY_SIZE];

        org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(privKey, 0, pubKey, 0);

        return pubKey;
    }

    public static byte[] sign(byte[] privkey, byte[] message) {
        byte[] sig = new byte[org.bouncycastle.math.ec.rfc8032.Ed25519.SIGNATURE_SIZE];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(privkey, 0, message, 0, message.length, sig, 0);
        return sig;
    }

    public static boolean verify(byte[] pubkey, byte[] sig, byte[] message) {
        return org.bouncycastle.math.ec.rfc8032.Ed25519.verify(sig, 0, pubkey, 0, message, 0, message.length);
    }
}
