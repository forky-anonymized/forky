package core

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"testing"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

type Triple struct {
    x, y, z int
}

var reorg_types = make(map[Triple]bool)

type TreeBlock struct {
	ethBlock *types.Block
	depth int
	Parent *TreeBlock
	Children []*TreeBlock
}

func bytesToString(data []byte) string {
    result := ""
    for _, b := range data {
        result += fmt.Sprintf("\\x%02x", b)
        if b >= 32 && b <= 126 { // ASCII printable characters
            result += string(b)
        }
    }
    return result
}

func calculateSHA256(str string) string {
    hash := sha256.Sum256([]byte(str))
    return fmt.Sprintf("%x", hash[:8])
}

func findNonLeafNodes(root *TreeBlock, result *[]*TreeBlock, visited map[*TreeBlock]bool) {
    if _, ok := visited[root]; !ok && len(root.Children) > 0 {
        *result = append(*result, root)
        visited[root] = true
    }
    for _, child := range root.Children {
        findNonLeafNodes(child, result, visited)
    }
}

func traverseTreeBlock(root *TreeBlock, result *[]*TreeBlock, visited map[*TreeBlock]bool) {
    if _, ok := visited[root]; !ok {
        *result = append(*result, root)
        visited[root] = true
    }
    for _, child := range root.Children {
        traverseTreeBlock(child, result, visited)
    }
}

func sortTreeBlocksByDepth(blocks []*TreeBlock) {
    sort.Slice(blocks, func(i, j int) bool {
        return blocks[i].depth > blocks[j].depth
    })
}

func find_depth(root *TreeBlock) (*TreeBlock) {
	var blocks []*TreeBlock
    visited := make(map[*TreeBlock]bool)
	traverseTreeBlock(root, &blocks, visited)
	sortTreeBlocksByDepth(blocks)

	return blocks[0]
}

func find_balance(root *TreeBlock) (*TreeBlock) {
    var blocks []*TreeBlock
    visited := make(map[*TreeBlock]bool)
    traverseTreeBlock(root, &blocks, visited)
    sortTreeBlocksByDepth(blocks)

    maxDepth := blocks[0].depth
    for _, block := range blocks {
        if block.depth < maxDepth {
            return block
        }
    }

	return blocks[0]
}

func find_breadth(root *TreeBlock) (*TreeBlock) {
    var nonLeafNodes []*TreeBlock
    visited := make(map[*TreeBlock]bool)
    findNonLeafNodes(root, &nonLeafNodes, visited)

    rand.Seed(time.Now().UnixNano())
	if len(nonLeafNodes) == 0 { return find_depth(root) }
    return nonLeafNodes[rand.Intn(len(nonLeafNodes))]
}

func get_next_block(data []byte, tree_root *TreeBlock, method int, blockchain *BlockChain, db ethdb.Database, logger *log.Logger) (*types.Block, error) {

	block := &types.Block{}
	
	parent := tree_root
	switch method % 3 {
	case 0:
		parent = find_depth(tree_root)
	case 1:
		parent = find_breadth(tree_root)
	case 2:
		parent = find_balance(tree_root)
	}
	// New TreeBlock
	block = makeBlockChain(parent.ethBlock, 1, ethash.NewFaker(), db, method)[0]

	new_treeblock := &TreeBlock{ethBlock: block, depth: parent.depth + 1, Parent: parent}
	parent.Children = append(parent.Children, new_treeblock)

	return block, nil
}

func FuzzForky(f *testing.F) {
	file, err := os.Create("test.log")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// Generate Seed
	// Initialize empty blockchain
	// var (
	// 	dbs      = rawdb.NewMemoryDatabase()
	// 	_ = new(Genesis).MustCommit(dbs)
	// )

	// // Initialize a fresh chain with only a genesis block
	// bc, _ := NewBlockChain(dbs, nil, params.AllEthashProtocolChanges, ethash.NewFaker(), vm.Config{}, nil, nil)

	// bks := makeBlockChain(bc.CurrentBlock(), 10, ethash.NewFaker(), dbs, 2)

	// var blockBytes [][]byte
	// blockBytes = append(blockBytes, []byte{0x10}) // Convert 0x10 to a byte slice
	
	// for _, block := range bks {
	// 	var buf = bytes.NewBuffer(make([]byte, 0, 32000))
	// 	if err := rlp.Encode(buf, block); err != nil { fmt.Print(err); return }
	// 	// fmt.Println("Block hash: ", block.Hash(), "length: ", len(buf.Bytes()))
	// 	blockBytes = append(blockBytes, []byte{0xff})
	// 	blockBytes = append(blockBytes, []byte{byte(len(buf.Bytes()))}) // Convert the length to a byte value
	// 	blockBytes = append(blockBytes, buf.Bytes())

	// 	// test
	// 	decoded_block := new(types.Block)
	// 	if err := rlp.Decode(buf, decoded_block); err != nil { fmt.Print(err); return }
	// 	// fmt.Println(block.Header())
	// 	// fmt.Println(decoded_block.Header())

	// 	if block.Header().Hash() != decoded_block.Header().Hash() { fmt.Println("Hashes don't match"); return }
	// }

	// dataBytes := bytes.Join(blockBytes, []byte(""))
	// f.Add(dataBytes)
	// // fmt.Println("Seed corpus added, length: ", len(dataBytes))
	// bc.Stop()


	f.Fuzz(
		func(t *testing.T, data []byte) {
			file, err := os.OpenFile("test.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			hexData := bytesToString(data)
			str := "go test fuzz v1\n[]byte(\"" + hexData + "\")\n"
			filename := calculateSHA256(str)

			logger := log.New(file, "", log.LstdFlags)
			// Initialize empty blockchain
			var (
				db      = rawdb.NewMemoryDatabase()
				_ = new(Genesis).MustCommit(db)
			)

			// Initialize a fresh chain with only a genesis block
			blockchain, _ := NewBlockChain(db, nil, params.AllEthashProtocolChanges, ethash.NewFaker(), vm.Config{}, nil, nil)
			defer blockchain.Stop()

			fuzzConsumer := fuzz.NewConsumer(data)
			// Number of blocks: 1 byte
			num_blocks, _ := fuzzConsumer.GetInt()
			// logger.Println("Number of blocks: ", num_blocks, num_blocks % 10)
			num_blocks = num_blocks % 32 + 1

			// Tree view
			tree_root := &TreeBlock{ethBlock: blockchain.CurrentBlock(), depth: int(blockchain.CurrentBlock().NumberU64())}

			nth_reorg := 0
			found_new_state := false
			for i := 0; i < num_blocks; i++ {
				// Create new block to process
				method, err := fuzzConsumer.GetInt()
				if err != nil { logger.Printf("Number of blocks: %d, but not enough bytes", num_blocks); t.SkipNow() }

				block, err := get_next_block(data, tree_root, method, blockchain, db, logger)
				if err != nil {
					logger.Println("Error creating a block: ", err)
					t.SkipNow()
				}

				// tip_before := blockchain.CurrentBlock().NumberU64()


				// Process the block
				n_replacing, n_replaced, err_int, err := blockchain.InsertChain2([]*types.Block{block})
				if n_replacing != -1 || n_replaced != -1 { 
					logger.Println("nth_reorg, n_replacing, n_replaced: ", nth_reorg, n_replacing, n_replaced)
					nth_reorg += 1
				} else {
					// logger.Println("No_reorg")
				}
				if err != nil { println(err_int, err.Error()) }


				new_state := Triple{int(nth_reorg), int(n_replacing), int(n_replaced)}
				if _, ok := reorg_types[new_state]; !ok {
					reorg_types[new_state] = true
					found_new_state = true
				}

				// tip_after := blockchain.CurrentBlock().NumberU64()
				// logger.Printf("Block hash: %x, parent hash: %x", block.Hash(), block.ParentHash())
				// logger.Println("** Tip before: ", tip_before, "Tip after: ", tip_after)
			}
			// logger.Println("----------------------------------------------------------")

			// test
			if found_new_state {
				file, err := os.Create("./corpus/FuzzForky/" + filename)
				if err != nil {
					log.Fatal(err)
				}
				
				// Write the string to the file
				_, err = file.WriteString(str)
				if err != nil {
					log.Fatal(err)
				}
				
				// Close the file
				err = file.Close()
				if err != nil {
					log.Fatal(err)
				}
			}
		})
}