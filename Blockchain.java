package securevoting;

import java.util.ArrayList;
import java.util.List;

public class Blockchain {
    private List<Block> chain;
    private int difficulty;
    private List<EncryptedVote> pendingVotes;

    public Blockchain(int difficulty) {
        this.chain = new ArrayList<>();
        this.difficulty = difficulty;
        this.pendingVotes = new ArrayList<>();
        // Create the genesis block
        createGenesisBlock();
    }

    private void createGenesisBlock() {
        Block genesisBlock = new Block("0", new ArrayList<>());
        genesisBlock.mineBlock(difficulty);
        chain.add(genesisBlock);
    }

    public Block getLatestBlock() {
        return chain.get(chain.size() - 1);
    }

    public void addVote(EncryptedVote vote) {
        pendingVotes.add(vote);
    }

    public void minePendingVotes() {
        Block block = new Block(getLatestBlock().getHash(), new ArrayList<>(pendingVotes));
        block.mineBlock(difficulty);
        chain.add(block);
        pendingVotes.clear();
    }

    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block currentBlock = chain.get(i);
            Block previousBlock = chain.get(i - 1);

            if (!currentBlock.getHash().equals(currentBlock.calculateHash())) {
                return false;
            }

            if (!currentBlock.getPreviousHash().equals(previousBlock.getHash())) {
                return false;
            }
        }
        return true;
    }

    public List<EncryptedVote> getAllVotes() {
        List<EncryptedVote> allVotes = new ArrayList<>();
        for (Block block : chain) {
            allVotes.addAll(block.getVotes());
        }
        return allVotes;
    }

    public List<Block> getChain() {
        return chain;
    }

    public int getDifficulty() {
        return difficulty;
    }

    public void setDifficulty(int difficulty) {
        this.difficulty = difficulty;
    }
}