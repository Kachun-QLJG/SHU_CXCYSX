package DemoChain

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

type Block struct {
	Index int64						//序号
	Timestamp int64					//当前时间戳
	ApplyTime string				//申请时间
	PrevBlockHash string			//上一节点的哈希值
	AuthorUsername string			//作者账号
	AuthorId string 				//作者身份证
	FileHash string					//申请专利的文件的哈希值
	Author string					//作者姓名
	AuthorityUsername string		//权力机构的账户名
	Hash string						//当前节点的哈希值
}

func calculateHash(b Block) string {
	blockData := strconv.FormatInt(b.Index, 10) + strconv.FormatInt(b.Timestamp, 10) + b.PrevBlockHash + b.AuthorId + b.FileHash + b.Author + b.ApplyTime + b.AuthorUsername + b.AuthorityUsername
	hashInBytes := sha256.Sum256([]byte(blockData))
	return hex.EncodeToString(hashInBytes[:])
}

func GenerateNewBlock(preBlock Block, applyTime string, authorId string, fileHash string, authorUsername string, author string, authorityUsername string) Block {
	newBlock := Block{}
	newBlock.Index = preBlock.Index + 1
	newBlock.PrevBlockHash = preBlock.Hash
	newBlock.Timestamp = time.Now().Unix()
	newBlock.FileHash = fileHash
	newBlock.AuthorId = authorId
	newBlock.Author = author
	newBlock.ApplyTime = applyTime
	newBlock.AuthorityUsername = authorityUsername
	newBlock.AuthorUsername = authorUsername
	newBlock.Hash = calculateHash(newBlock)
	return newBlock
}

func GenerateGenesisBlock() Block {
	preBlock := Block{}
	preBlock.Index = -1
	preBlock.Hash = ""
	preBlock.Timestamp = time.Now().Unix()
	fileHash := "申请专利的文件的哈希值"
	author := "作者名字"
	authorId := "作者身份信息"
	applyTime := "申请时间"
	authorUsername := "作者账号"
	authorityUsername := "权力机构的账户名"
	return GenerateNewBlock(preBlock, applyTime, authorId, fileHash, authorUsername, author, authorityUsername)
}
