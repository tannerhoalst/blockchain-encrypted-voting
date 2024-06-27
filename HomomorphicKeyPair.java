package securevoting;

import java.math.BigInteger;

public class HomomorphicKeyPair {
    private final BigInteger n;
    private final BigInteger g;
    private final BigInteger lambda;
    private final BigInteger mu;

    public HomomorphicKeyPair(BigInteger n, BigInteger g, BigInteger lambda, BigInteger mu) {
        this.n = n;
        this.g = g;
        this.lambda = lambda;
        this.mu = mu;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getLambda() {
        return lambda;
    }

    public BigInteger getMu() {
        return mu;
    }
}