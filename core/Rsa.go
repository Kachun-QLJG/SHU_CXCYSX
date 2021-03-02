package DemoChain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

func RsaGenUserKey(bits int) error{		//生成用户公钥私钥文件
	// 一、生成私钥
	// 1. 使用rsa包内的GenerateKey生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	// 2. 通过x509标准将私钥转化为ASN.1的DER编码字符串
	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	// 3. 将私钥字符串设置到pem格式块中
	block := pem.Block{
		Type: "RSA Private Key",
		Bytes: privateStream,
	}
	// 4. 通过pem将设置好的数据进行编码，并写入磁盘文件
	privateFile, err := os.Create("E:/Key/Users/private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(privateFile, &block)
	if err != nil {
		return err
	}
	err = privateFile.Close()
	if err != nil {
		return err
	}
	// 二、取出公钥
	// 1. 从得到的私钥对象中将公钥信息取出
	publicKey := privateKey.PublicKey
	// 2. 通过x509标准将得到的rsa公钥序列化为字符串
	publicStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}
	// 3. 将公钥字符串设置到pem格式块中
	block = pem.Block{
		Type: "RSA Public Key",
		Bytes: publicStream,
	}
	// 4. 通过pem将设置好的数据进行编码，并写入磁盘文件
	publicFile, err := os.Create("E:/Key/Users/public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(publicFile, &block)
	if err != nil {
		return err
	}
	err = publicFile.Close()
	if err != nil {
		return err
	}
	return nil
}
/**
func RsaGenAuthorityKey(bits int) error{		//生成权力机构公钥私钥文件
	// 一、生成私钥
	// 1. 使用rsa包内的GenerateKey生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	// 2. 通过x509标准将私钥转化为ASN.1的DER编码字符串
	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	// 3. 将私钥字符串设置到pem格式块中
	block := pem.Block{
		Type: "RSA Private Key",
		Bytes: privateStream,
	}
	// 4. 通过pem将设置好的数据进行编码，并写入磁盘文件
	privateFile, err := os.Create("Key/Authority/private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(privateFile, &block)
	if err != nil {
		return err
	}
	err = privateFile.Close()
	if err != nil {
		return err
	}
	// 二、取出公钥
	// 1. 从得到的私钥对象中将公钥信息取出
	publicKey := privateKey.PublicKey
	// 2. 通过x509标准将得到的rsa公钥序列化为字符串
	publicStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}
	// 3. 将公钥字符串设置到pem格式块中
	block = pem.Block{
		Type: "RSA Public Key",
		Bytes: publicStream,
	}
	// 4. 通过pem将设置好的数据进行编码，并写入磁盘文件
	publicFile, err := os.Create("Key/Authority/public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(publicFile, &block)
	if err != nil {
		return err
	}
	err = publicFile.Close()
	if err != nil {
		return err
	}
	return nil
}
**/
func ReadParsePublicKey(filename string) (*rsa.PublicKey, error) {	//读取公钥文件，解析公钥对象
	// 1、读取公钥文件，获取公钥字节
	publicKeyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	// 2、解码公钥字节，生成加密对象
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, errors.New("公钥信息错误！")
	}
	// 3、解析DER编码的公钥，生成公钥接口
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 4、公钥接口转型成公钥对象
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	return publicKey, nil
}

func ReadParsePrivateKey(filename string) (*rsa.PrivateKey, error) {	//读取私钥文件，解析出私钥对象
	// 1、读取私钥文件，获取私钥字节
	privateKeyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	// 2、解码私钥字节，生成加密对象
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("私钥信息错误！")
	}
	// 3、解析DER编码的私钥，生成私钥对象
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
/********************************************************************************/

func RSASign(data []byte, filename string) (string, error) {	//签名算法
	// 1、选择hash算法，对需要签名的数据进行hash运算
	myhash := crypto.SHA256
	hashInstance := myhash.New()
	hashInstance.Write(data)
	hashed := hashInstance.Sum(nil)
	// 2、读取私钥文件，解析出私钥对象
	privateKey, err := ReadParsePrivateKey(filename)
	if err != nil {
		return "私钥读取失败！请检查私钥文件", err
	}
	// 3、RSA数字签名（参数是随机数、私钥对象、哈希类型、签名文件的哈希串，生成bash64编码）
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, myhash, hashed)
	if err != nil {
		return "签名失败：", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func RSAVerify(data []byte, base64Sig, filename string) error {	//公钥验证
	// 1、对base64编码的签名内容进行解码，返回签名字节
	bytes, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return err
	}
	// 2、选择hash算法，对需要签名的数据进行hash运算
	myhash := crypto.SHA256
	hashInstance := myhash.New()
	hashInstance.Write(data)
	hashed := hashInstance.Sum(nil)
	// 3、读取公钥文件，解析出公钥对象
	publicKey, err := ReadParsePublicKey(filename)
	if err != nil {
		return err
	}
	// 4、RSA验证数字签名（参数是公钥对象、哈希类型、签名文件的哈希串、签名后的字节）
	return rsa.VerifyPKCS1v15(publicKey, myhash, hashed, bytes)
}

