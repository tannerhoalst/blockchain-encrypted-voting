package securevoting;

import java.math.BigInteger;
import java.util.Objects;

public class Proof {
    private final BigInteger c;
    private final BigInteger z;
    private final BigInteger r;

    public Proof(BigInteger c, BigInteger z, BigInteger r) {
        this.c = c;
        this.z = z;
        this.r = r;
    }

    public BigInteger getC() {
        return c;
    }

    public BigInteger getZ() {
        return z;
    }

    public BigInteger getR() {
        return r;
    }

    @Override
    public String toString() {
        return "Proof{" +
                "c=" + c +
                ", z=" + z +
                ", r=" + r +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Proof proof = (Proof) o;
        return Objects.equals(c, proof.c) &&
                Objects.equals(z, proof.z) &&
                Objects.equals(r, proof.r);
    }

    @Override
    public int hashCode() {
        return Objects.hash(c, z, r);
    }
}