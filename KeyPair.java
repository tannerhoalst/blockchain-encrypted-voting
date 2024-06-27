package securevoting;

import java.math.BigInteger;

public class KeyPair {
    private final BigInteger publicKey;
    private final BigInteger privateKey;

    public KeyPair(BigInteger publicKey, BigInteger privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }
}