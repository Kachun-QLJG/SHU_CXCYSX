package main

import (
	DemoChain "Gin_Demochain/core"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/howeyc/gopass"
	"io"
	"os"
	"os/exec"
)

func gethash(path string) (hash string) {
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		fmt.Printf("打开文件%s失败，请检查文件目录。\n", path)
		return
	} else {
		h1 := sha256.New()
		_, err := io.Copy(h1, file)
		if err == nil {
			hash := h1.Sum(nil)
			hashValue := hex.EncodeToString(hash)
			return hashValue
		} else {
			return "哈希生成遇未知错误"
		}
	}

}
func createPemFiles(){	//如果文件不存在，在E:/Key/Users/生成新的公私钥。
	fmt.Println("未在路径”E:/Key/Users“下找到曾经生成过的公钥与私钥！")
	_ = os.MkdirAll("E:/Key/Users/", 777)
	err := DemoChain.RsaGenUserKey(1024)
	if err != nil {
		fmt.Println("用户密钥生成错误：", err)
	} else {		//生成成功
		fmt.Println("已成功生成新的公钥与私钥！")
		fmt.Println("")
		fmt.Println("【警告】请勿轻易删除”E:/Key/Users/“下的文件！")
		fmt.Println("")
		fmt.Println("-----------------------------------------")
		pemHash := gethash("E:/Key/Users/public.pem")
		fmt.Println("本次生成的公钥文件的哈希值为：【请将下列字段复制黏贴到网页上“公钥文件哈希值”栏】")
		fmt.Println(pemHash)
		fmt.Println("")
		fmt.Println("-----------------------------------------")
		pemHash = gethash("E:/Key/Users/private.pem")
		fmt.Println("本次生成的私钥文件的哈希值为：【请将下列字段复制黏贴到网页上“私钥文件哈希值”栏】")
		fmt.Println(pemHash)
		fmt.Println("")
		fmt.Println("-----------------------------------------")
	}
}

func main(){
	_, err := os.Stat("E:/Key/Users/private.pem")
	if os.IsNotExist(err) {	//如果文件不存在
		createPemFiles()
	}

	WELCOME: {
		exec.Command("cls")
		fmt.Println("欢迎使用版权记录系统！","请输入您的账号：")
		var users1,users2 string
		_,err := fmt.Scanln(&users1)
		if err != nil {
			fmt.Println("账号输入异常，请重新输入！")
			goto WELCOME
		}
		fmt.Println("请再次输入您的账号：")
		_,err = fmt.Scanln(&users2)
		if err != nil {
			fmt.Println("账号输入异常，请重新输入！")
			goto WELCOME
		}
		if users1 != users2 {
			fmt.Println("两次输入的账号不一致！请检查后重新输入！")
			goto WELCOME
		} else{
			fmt.Println("您的账号为：", users1, "。请输入您的密码：")
			pass1,err := gopass.GetPasswdMasked()
			if err != nil {
				fmt.Println("密码输入异常，请重新输入！")
				goto WELCOME
			}
			fmt.Println("请再次输入您的密码：")
			pass2,_ := gopass.GetPasswdMasked()
			if err != nil {
				fmt.Println("密码输入异常，请重新输入！")
				goto WELCOME
			}
			password1 := string(pass1)
			password2 := string(pass2)
			if password1 != password2 {
				fmt.Println("两次输入的密码不一致！请检查后重新输入！")
				goto WELCOME
			} else{						// 至此，账号密码输入结束。输入的账号 与 密码的哈希值（与服务器端相同的哈希算法） 将会被用作验证。
				pass := sha256.Sum256([]byte(password1))
				password := hex.EncodeToString(pass[:])		//得到本地输入的密码的哈希值

				var filePath, userName, id, randStr string
				fmt.Println("用户",users1,"您好！为了确保密文正确生成，请注意不要输入空格等无关的字符，谢谢！")
				fmt.Println("若您发现任何一步输入错误，请关闭程序，并重新打开。")
				fmt.Println("")
				FILE:
				fmt.Println("-----------------------------------------")
				fmt.Println("请您输入您的文件的相对地址：")
				_,_ = fmt.Scanln(&filePath)
				fileHash := gethash(filePath)
				if fileHash == "" {
					goto FILE
				}
				fmt.Println("")
				fmt.Println("-----------------------------------------")
				fmt.Println("请您输入页面中的随机字符串：")
				_,_ = fmt.Scanln(&randStr)
				fmt.Println("")
				fmt.Println("-----------------------------------------")
				fmt.Println("-----------------------------------------")
				fmt.Println("请您输入您的姓名：")
				_,_ = fmt.Scanln(&userName)
				fmt.Println("")
				fmt.Println("-----------------------------------------")
				fmt.Println("请您输入您的证件号码：")
				_,_ = fmt.Scanln(&id)
				fmt.Println("")
				fmt.Println("-----------------------------------------")
				fmt.Println("您的文件哈希值为：【请将下列字段复制黏贴到网页上“文件哈希值”栏】")
				fmt.Println(fileHash)
				data := fileHash + " -&@&- " + userName + " -&@&- " + id
				piece1 := sha256.Sum256([]byte(data))	//算原话的哈希
				str1 := hex.EncodeToString(piece1[:])	//算好保存为字符串
				sig1, err := DemoChain.RSASign([]byte(str1), "E:/Key/Users/private.pem")//用用户的私钥对文件的哈希值进行签名
				if err != nil {
					fmt.Println("对文件哈希值签名失败：", err)
				}
				fmt.Println("您的数字签名为：【请将下列字段复制黏贴到网页上“数字签名”栏】")
				fmt.Println(sig1)
				pemHash := gethash("E:/Key/Users/private.pem")
				fmt.Println("本次私钥文件的哈希值为：【请将下列字段复制黏贴到网页上“私钥文件哈希值”栏】")	//用以匹配公钥文件。
				fmt.Println(pemHash)
				var total string
				total = fileHash + " -#@#- " + userName + " -#@#- " + id + " -#@#- " + users1 + " -#@#- " + password + " -#@#- " + pemHash + " -#@#- " + sig1 + " -#@#- " + randStr
				tempHash1 := sha256.Sum256([]byte(total))
				hash1 := hex.EncodeToString(tempHash1[:])
				hash1 += password
				tempHash2 := sha256.Sum256([]byte(hash1))
				hash2 := hex.EncodeToString(tempHash2[:])
				fmt.Println("本次生成的验证码为：【请将下列字段复制黏贴到网页上“验证码”栏】")
				fmt.Println(hash2)
				fmt.Println("-------------------------------------------")
				fmt.Println("本次验证码生成已完成。")
				fmt.Println("按回车键继续...")
				var input string
				_,_ =fmt.Scanln(&input)
			}
		}
	}

}