package DemoChain

import (
	"fmt"
	"log"
)

type Blockchain struct {
	Blocks []*Block
}

func NewBlockchain() *Blockchain {
	genesisBlock := GenerateGenesisBlock()
	blockchain := Blockchain{}
	blockchain.AppendBlock(&genesisBlock)
	return &blockchain
}

func (bc *Blockchain) SendData(applyTime string, authorId string, fileHash string, authorUsername string, author string, authorityUsername string) (index int64, preHash string, curHash string, timestamp int64){
	preBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := GenerateNewBlock(*preBlock, applyTime, authorId, fileHash, authorUsername, author, authorityUsername)
	bc.AppendBlock(&newBlock)
	return newBlock.Index, newBlock.PrevBlockHash, newBlock.Hash, newBlock.Timestamp
}

func (bc *Blockchain) AppendBlock(newBlock *Block) {
	if len(bc.Blocks) == 0 {
		bc.Blocks = append(bc.Blocks, newBlock)
		return
	}
	if isValid(*newBlock, *bc.Blocks[len(bc.Blocks)-1]) {
		bc.Blocks = append(bc.Blocks, newBlock)
	} else {
		log.Fatal("invalid block")
	}
}

func (bc *Blockchain) Print() {
	for _, block := range bc.Blocks {
		fmt.Printf("编号: %d\n", block.Index)
		fmt.Printf("该节点创建时间: %s\n", block.Timestamp)
		fmt.Printf("该请求申请时间: %s\n", block.ApplyTime)
		fmt.Printf("前一节点哈希值: %s\n", block.PrevBlockHash)
		fmt.Printf("作者账号: %s\n", block.AuthorUsername)
		fmt.Printf("作者身份信息: %s\n", block.AuthorId)
		fmt.Printf("申请专利的文件的哈希值: %s\n", block.FileHash)
		fmt.Printf("申请专利人: %s\n", block.Author)
		fmt.Printf("审核权力机构用户名: %s\n", block.AuthorityUsername)
		fmt.Printf("当前节点哈希值: %s\n", block.Hash)
	}
}

func isValid(newBlock Block, oldBlock Block) bool {
	if newBlock.Index-1 != oldBlock.Index {
		return false
	}
	if newBlock.PrevBlockHash != oldBlock.Hash {
		return false
	}
	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}
	return true
}
