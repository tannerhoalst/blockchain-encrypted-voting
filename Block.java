package securevoting;

import java.util.List;
import java.util.Date;

public class Block {
    private String hash;
    private String previousHash;
    private List<EncryptedVote> votes;
    private long timeStamp;
    private int nonce;

    public Block(String previousHash, List<EncryptedVote> votes) {
        this.previousHash = previousHash;
        this.votes = votes;
        this.timeStamp = new Date().getTime();
        this.hash = calculateHash();
    }

    public String calculateHash() {
        String dataToHash = previousHash 
                + Long.toString(timeStamp) 
                + Integer.toString(nonce)
                + votes.toString();
        return CryptographicUtils.applySha256(dataToHash);
    }

    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0');
        while(!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block Mined!!! : " + hash);
    }

    public String getHash() {
        return hash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public List<EncryptedVote> getVotes() {
        return votes;
    }

    public long getTimeStamp() {
        return timeStamp;
    }
}