package securevoting;

import java.math.BigInteger;

public class EncryptedVote {
    private final BigInteger encryptedVote;
    private final Proof proof;
    private final BigInteger voterPublicKey;  // New field

    private EncryptedVote(BigInteger encryptedVote, Proof proof, BigInteger voterPublicKey) {
        this.encryptedVote = encryptedVote;
        this.proof = proof;
        this.voterPublicKey = voterPublicKey;
    }

    public static EncryptedVote create(BigInteger encryptedVote, Proof proof, BigInteger voterPublicKey) {
        return new EncryptedVote(encryptedVote, proof, voterPublicKey);
    }

    public BigInteger getEncryptedVote() {
        return encryptedVote;
    }

    public Proof getProof() {
        return proof;
    }

    public BigInteger getVoterPublicKey() {
        return voterPublicKey;
    }

    @Override
    public String toString() {
        return "EncryptedVote{" +
               "encryptedVote=" + encryptedVote +
               ", proof=" + proof +
               ", voterPublicKey=" + voterPublicKey +
               '}';
    }
}