package securevoting;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptographicUtils {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int HOMOMORPHIC_KEY_SIZE = 2048; // Can be increased to 3072 for higher security

    public static KeyPair generateKeyPair(BigInteger p, BigInteger g) {
        BigInteger privateKey = new BigInteger(p.bitLength() - 1, RANDOM);
        BigInteger publicKey = g.modPow(privateKey, p);
        return new KeyPair(publicKey, privateKey);
    }

    public static HomomorphicKeyPair generateHomomorphicKeyPair() {
        BigInteger p = BigInteger.probablePrime(HOMOMORPHIC_KEY_SIZE / 2, RANDOM);
        BigInteger q = BigInteger.probablePrime(HOMOMORPHIC_KEY_SIZE / 2, RANDOM);
        BigInteger n = p.multiply(q);
        BigInteger nsquare = n.multiply(n);
        BigInteger g = n.add(BigInteger.ONE);
        BigInteger lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        BigInteger mu = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return new HomomorphicKeyPair(n, g, lambda, mu);
    }

    public static BigInteger encrypt(BigInteger m, BigInteger n, BigInteger g) {
        BigInteger nsquare = n.multiply(n);
        BigInteger r = new BigInteger(n.bitLength(), RANDOM).mod(n);
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    public static BigInteger decrypt(BigInteger c, HomomorphicKeyPair keys) {
        BigInteger nsquare = keys.getN().multiply(keys.getN());
        return c.modPow(keys.getLambda(), nsquare)
                .subtract(BigInteger.ONE)
                .divide(keys.getN())
                .multiply(keys.getMu())
                .mod(keys.getN());
    }

    public static Proof generateProof(BigInteger privateKey, BigInteger publicKey, int vote, BigInteger encryptedVote, BigInteger n, BigInteger p, BigInteger g) {
        BigInteger r = new BigInteger(p.bitLength(), RANDOM).mod(p);
        BigInteger a = g.modPow(r, p);
        BigInteger b = publicKey.modPow(r, p);
        BigInteger c = hash(p, publicKey, g.modPow(BigInteger.valueOf(vote), p), a, b, encryptedVote);
        BigInteger z = r.add(c.multiply(privateKey)).mod(p.subtract(BigInteger.ONE));
        if (z.signum() < 0) {
            z = z.add(p.subtract(BigInteger.ONE));
        }
        Proof proof = new Proof(c, z, r);
        return proof;
    }
    
    public static boolean verifyProof(BigInteger publicKey, BigInteger encryptedVote, Proof proof, BigInteger n, BigInteger p, BigInteger g) {
        BigInteger a = g.modPow(proof.getR(), p);
        BigInteger b = publicKey.modPow(proof.getZ(), p);
        
        BigInteger leftSide = g.modPow(proof.getZ(), p);
        BigInteger rightSide = a.multiply(publicKey.modPow(proof.getC(), p)).mod(p);
        boolean equation1Valid = leftSide.equals(rightSide);
        
        BigInteger leftSide2 = publicKey.modPow(proof.getZ(), p);
        BigInteger rightSide20 = b.multiply(g.modPow(BigInteger.ZERO, p).modPow(proof.getC(), p)).mod(p);
        BigInteger rightSide21 = b.multiply(g.modPow(BigInteger.ONE, p).modPow(proof.getC(), p)).mod(p);
        boolean equation2Valid = leftSide2.equals(rightSide20) || leftSide2.equals(rightSide21);
        
        return equation1Valid && equation2Valid;
    }

    public static BigInteger hash(BigInteger p, BigInteger... inputs) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (BigInteger input : inputs) {
                digest.update(bigIntegerToBytes(input));
            }
            byte[] hashBytes = digest.digest();
            return new BigInteger(1, hashBytes).mod(p);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] bigIntegerToBytes(BigInteger bi) {
        byte[] bytes = bi.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }

    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}