/**
package main


import (
	DemoChain "Gin_Demochain/core"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func UserSign(fileHash string, userName string, id string) (string, string, string, string, string, string) {
	//用户向权力机构提交文件（没写）、文件哈希、个人身份信息，并用私钥对上述信息签名【该函数应发生在用户本地】
	userID := userName + "@" + id
	sig1, err := DemoChain.RSASign([]byte(fileHash), "Key/Users/private.pem")//用用户的私钥对文件的哈希值进行签名
	if err != nil {
		fmt.Println("对文件哈希值签名失败：", err)
	}
	piece := sha256.Sum256([]byte(userID))	//算用户身份的哈希
	str1 := hex.EncodeToString(piece[:])	//算好保存为字符串
	sig2, err := DemoChain.RSASign([]byte(str1), "Key/Users/private.pem")//用用户的私钥对哈希后的字符串签名
	if err != nil {
		fmt.Println("对个人身份签名失败：", err)
	}
	var pack string
	pack = fileHash + sig1 + userID + str1 + sig2
	piece = sha256.Sum256([]byte(pack))	//上述五个内容的哈希值
	hash := hex.EncodeToString(piece[:])	//保存为字符串
	return fileHash, sig1, userID, str1, sig2, hash
}

func AuthJudge(fileHash string, userName string, id string, authID string, bc *DemoChain.Blockchain) {
	//该函数首先验证从用户获得的消息，然后进行审核，审核通过的再发送到区块链【审核部分略去，默认审核通过】
	fileHash, sig1, userID, str1, sig2, hash := UserSign(fileHash, userName, id)
	//区块链上网后，这六个字符串应该是直接获得，而不是通过调用函数计算得到的
	var pack string	//验证传输过程中消息没有被篡改
	pack = fileHash + sig1 + userID + str1 + sig2
	piece := sha256.Sum256([]byte(pack))	//算得到的消息的哈希
	realHash := hex.EncodeToString(piece[:])	//保存为字符串
	if realHash != hash {
		fmt.Println("【错误】该消息已被篡改！")
		return	//区块链上网后，这里理论上应该是直接转到错误页面
	} else {	//消息没有被篡改
		judge := "PASS"	//默认通过
		if judge == "PASS" {
			authorPiece := strings.Split(userID, "@")
			author := authorPiece[0]	//得到专利申请人的名字
			var data string
			data = fileHash + " -&@&- " + sig1 + " -&@&- " + userID + " -&@&- " + str1 + " -&@&- " + sig2
			piece = sha256.Sum256([]byte(data))  //上述内容的哈希值
			hash1 := hex.EncodeToString(piece[:]) //保存为字符串
			sig3, err := DemoChain.RSASign([]byte(hash1), "Key/Authority/private.pem")//用权力机构的私钥对消息的哈希值进行签名
			if err != nil {
				fmt.Println("对消息签名失败：", err)
			}
			piece := sha256.Sum256([]byte(authID))	//算权力机构身份的哈希
			hash2 := hex.EncodeToString(piece[:])	//算好保存为字符串
			sig4, err := DemoChain.RSASign([]byte(hash2), "Key/Authority/private.pem")//用权力机构的私钥对哈希后的字符串签名
			if err != nil {
				fmt.Println("对权力机构身份签名失败：", err)
			}
			bc.SendData(fileHash, author, data, hash1, sig3, authID, hash2, sig4)
		} else {
			fmt.Println("审核未通过！")
		}
	}
}

func unixToTime(timestamp int64) string {
	timeObj := time.Unix(timestamp, 0) //将时间戳转为时间格式
	year := timeObj.Year() //年
	month := timeObj.Month() //月
	day := timeObj.Day() //日
	hour := timeObj.Hour() //小时
	minute := timeObj.Minute() //分钟
	second := timeObj.Second() //秒
	var result string
	result = strconv.FormatInt(int64(year), 10)+"年"+strconv.FormatInt(int64(month), 10)+"月"+strconv.FormatInt(int64(day), 10)+"日"+strconv.FormatInt(int64(hour), 10)+"时"+strconv.FormatInt(int64(minute), 10)+"分"+strconv.FormatInt(int64(second), 10)+"秒"
	return result
}

func main() {
	bc := DemoChain.NewBlockchain()
	err := DemoChain.RsaGenUserKey(1024)
	if err != nil {
		fmt.Println("用户密钥生成错误：", err)
	}
	err = DemoChain.RsaGenAuthorityKey(1024)
	if err != nil {
		fmt.Println("用户密钥生成错误：", err)
	}
	AuthJudge("29BAADC4249BE31D1F63E7C14BAC31F1E49C7C8136044AD8B89ADE87158383A8", "奚嘉骏","19120246", "专利局工作人员-01", bc)//data.txt
	AuthJudge("97C01AF20042713D56EB139BF6EAF03B46C856C4C1F104BDB7F5E5DBF4298251", "夏逸凡","19120249", "专利局工作人员-01", bc)//data1.txt
	AuthJudge("0E102484338FF8F55766B332AB726E4C92A4748D84DD1B33320A0C15BD944BEB", "伍慕庭","19120248", "专利局工作人员-01", bc)//data2.txt
	AuthJudge("CAAC08AB7DC32A1935D58EBD03F9B08680CB8A1D30B931DF7046D1B74074C382", "周泽昊","19120247", "专利局工作人员-01", bc)//周泽昊头像.jpg

	bc.Print()

	fmt.Println("开始查询，目前查询为死循环：")
	for {
		fmt.Println("请输入文件哈希值：")
		reader:=bufio.NewReader(os.Stdin)
		temp,_,_:=reader.ReadLine()
		fileHash := string(temp)
		for i := 0; i < len(bc.Blocks); i++ {
			if bc.Blocks[i].FileHash == fileHash {
				fmt.Println("文件作者：", bc.Blocks[i].Author)
				fmt.Println("申请时间：", unixToTime(bc.Blocks[i].Timestamp))
				fmt.Println("审批者：", bc.Blocks[i].AuthorityID)
				//核验消息是否为真
				piece1 := sha256.Sum256([]byte(bc.Blocks[i].AuthorizedData))	//算原话的哈希
				str1 := hex.EncodeToString(piece1[:])	//算好保存为字符串
				err := DemoChain.RSAVerify([]byte(str1), bc.Blocks[i].AuthorizedSig1, "Key/Authority/public.pem")
				if err != nil {
					fmt.Println("【错误】验证权力机构消息签名失败：", err)
				} else {	//检查权力机构身份验证签名
					piece2 := sha256.Sum256([]byte(bc.Blocks[i].AuthorityID))	//算原话的哈希
					str2 := hex.EncodeToString(piece2[:])	//算好保存为字符串
					err := DemoChain.RSAVerify([]byte(str2), bc.Blocks[i].AuthorizedSig2, "Key/Authority/public.pem")
					if err != nil {
						fmt.Println("【错误】验证权力机构身份签名失败：", err)
					} else {	//检查申请人文件哈希值签名
						authorPiece := strings.Split(bc.Blocks[i].AuthorizedData, " -&@&- ")
						fileSign := authorPiece[1]	//得到专利申请人对文件的数字签名
						err := DemoChain.RSAVerify([]byte(bc.Blocks[i].FileHash), fileSign, "Key/Users/public.pem")
						if err != nil {
							fmt.Println("【错误】验证申请人文件签名失败：", err)
						} else {	//检查申请人身份哈希值签名
							id := authorPiece[2]	//得到专利申请人的身份信息
							idSign := authorPiece[4]//得到专利申请人的身份签名
							piece4 := sha256.Sum256([]byte(id))	//算原话的哈希
							str4 := hex.EncodeToString(piece4[:])	//算好保存为字符串
							err := DemoChain.RSAVerify([]byte(str4), idSign, "Key/Users/public.pem")
							if err != nil {
								fmt.Println("【错误】验证申请人身份签名失败：", err)
							} else {
								fmt.Println("所有签名验证成功！上述内容完全属实！")
							}
						}
					}
				}
				break
			} else {
				if i == len(bc.Blocks) - 1 {
					fmt.Println("区块链中不存在哈希值为", fileHash, "的文件！")
				}
			}
		}
		fmt.Println()
	}
}
**/