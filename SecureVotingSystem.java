package securevoting;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class SecureVotingSystem {
    public static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    public static final BigInteger G = BigInteger.valueOf(2);

    private static HomomorphicKeyPair electionKeys;
    private static Map<BigInteger, Boolean> registeredVoters = new HashMap<>();

    public static void initializeElection() {
        electionKeys = CryptographicUtils.generateHomomorphicKeyPair();
    }

    public static KeyPair registerVoter() {
        KeyPair voterKeys = CryptographicUtils.generateKeyPair(P, G);
        registeredVoters.put(voterKeys.getPublicKey(), false);
        return voterKeys;
    }

    public static EncryptedVote castVote(KeyPair voterKeys, int vote) {
        if (!registeredVoters.containsKey(voterKeys.getPublicKey())) {
            throw new IllegalArgumentException("Voter not registered");
        }
        if (registeredVoters.get(voterKeys.getPublicKey())) {
            throw new IllegalArgumentException("Voter has already cast a vote");
        }
        if (vote != 0 && vote != 1) {
            throw new IllegalArgumentException("Vote must be 0 or 1");
        }
        BigInteger encryptedVote = CryptographicUtils.encrypt(BigInteger.valueOf(vote), electionKeys.getN(), electionKeys.getG());
        Proof proof = CryptographicUtils.generateProof(voterKeys.getPrivateKey(), voterKeys.getPublicKey(), vote, encryptedVote, electionKeys.getN(), P, G);        
        registeredVoters.put(voterKeys.getPublicKey(), true);
        return EncryptedVote.create(encryptedVote, proof, voterKeys.getPublicKey());
    }
    
    public static boolean verifyVote(BigInteger voterPublicKey, EncryptedVote encryptedVote) {
        if (!registeredVoters.containsKey(voterPublicKey)) {
            System.out.println("Voter not registered: " + voterPublicKey);
            return false;
        }
        boolean proofValid = CryptographicUtils.verifyProof(voterPublicKey, encryptedVote.getEncryptedVote(), encryptedVote.getProof(), electionKeys.getN(), P, G);
        if (!proofValid) {
            System.out.println("Proof invalid for voter: " + voterPublicKey);
        }
        return proofValid;
    }
    
    public static BigInteger tallyVotes(List<EncryptedVote> allVotes) {
        BigInteger tally = BigInteger.ONE;
        for (EncryptedVote vote : allVotes) {
            tally = tally.multiply(vote.getEncryptedVote()).mod(electionKeys.getN().multiply(electionKeys.getN()));
        }
        return CryptographicUtils.decrypt(tally, electionKeys);
    }

    public static void main(String[] args) {
        // Initialize the voting system
        initializeElection();
    
        // Initialize the blockchain with a difficulty of 4
        Blockchain blockchain = new Blockchain(4);
    
        try {
            // Register voters
            KeyPair voter1 = registerVoter();
            KeyPair voter2 = registerVoter();
            KeyPair voter3 = registerVoter();
    
            // Cast votes
            EncryptedVote vote1 = castVote(voter1, 1);
            EncryptedVote vote2 = castVote(voter2, 0);
            EncryptedVote vote3 = castVote(voter3, 1);
    
            // Add votes to the blockchain and mine blocks
            System.out.println("\nMining block 1...");
            blockchain.addVote(vote1);
            blockchain.minePendingVotes();
    
            System.out.println("Mining block 2...");
            blockchain.addVote(vote2);
            blockchain.minePendingVotes();
    
            System.out.println("Mining block 3...");
            blockchain.addVote(vote3);
            blockchain.minePendingVotes();
    
            // Print out the blockchain
            System.out.println("\nBlockchain contents:");
            for (int i = 0; i < blockchain.getChain().size(); i++) {
                Block block = blockchain.getChain().get(i);
                System.out.println("Block " + i + " Hash: " + block.getHash());
                System.out.println("Block " + i + " Previous Hash: " + block.getPreviousHash());
                //System.out.println("Block " + i + " Votes: " + block.getVotes());
                System.out.println();
            }

            System.out.println("\nVerifying votes after adding to blockchain:");
            int totalVotes = 0;
            int validVotes = 0;
    
            List<EncryptedVote> allValidVotes = new LinkedList<>();
            for (Block block : blockchain.getChain()) {
                for (EncryptedVote vote : block.getVotes()) {
                    totalVotes++;
                    BigInteger voterPublicKey = getVoterPublicKeyForVote(vote);
                    if (verifyVote(voterPublicKey, vote)) {
                        validVotes++;
                        allValidVotes.add(vote);
                    } else {
                        System.out.println("Invalid vote found in block with hash: " + block.getHash());
                        System.out.println("Invalid vote's public key: " + voterPublicKey);
                    }
                }
            }
            System.out.println("Verification complete. " + validVotes + " out of " + totalVotes + " votes are valid.");
    
            // Verify the blockchain
            System.out.println("Is blockchain valid? " + blockchain.isChainValid());
    
            // Tally votes
            BigInteger result = tallyVotes(allValidVotes);
            System.out.println("\nTotal 'Yes' votes: " + result);
    
        } catch (IllegalArgumentException e) {
            System.out.println("Error in voting process: " + e.getMessage());
        }
    }

    private static BigInteger getVoterPublicKeyForVote(EncryptedVote vote) {
        return vote.getVoterPublicKey();
    }
}