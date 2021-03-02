package main

import "C"
import (
	DemoChain "Gin_Demochain/core"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dchest/captcha"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	path2 "path"
	"strings"
	"time"
)
var blockchain *DemoChain.Blockchain

type User struct {
	Username string		`gorm:"type:varchar(21);unique_index;not null;primary_key"`
	Passwords string	`gorm:"type:varchar(64);not null"`
}

type Authority struct {
	Username string		`gorm:"type:varchar(26);unique_index;not null;primary_key"`
	Passwords string	`gorm:"type:varchar(64);not null"`
}

type Application struct {
	Uptime string		`gorm:"type:varchar(30);not null;unique_index;primary_key"`		//申请提交信息时间
	Username string		`gorm:"type:varchar(20);not null"`		//用户名
	ApplyName string	`gorm:"type:varchar(90);not null"`		//申请人姓名
	ApplyId string		`gorm:"type:varchar(255);not null"`		//申请人证件号码
	FileHash string		`gorm:"type:varchar(64);not null"`		//文件哈希值
	FileName string		`gorm:"type:varchar(64);not null"`		//文件名【便于审核时下载】
	UpStatus string		`gorm:"type:varchar(10);not null"`		//上传验证状态
	VerStatus string	`gorm:"type:varchar(10);not null"`		//审核状态
	AuthAccount string	`gorm:"type:varchar(25)"`				//审核者
	AuthTime string		`gorm:"type:varchar(30)"`				//审核时间
	AuthText string		`gorm:"type:varchar(255)"`				//审核者返回的留言
}

type Chain struct {
	ID int				`gorm:"type:int;not null;unique_index;primary_key"`
	AuthTime int		`gorm:"type:int;not null"`				//审核时间
	Uptime string		`gorm:"type:varchar(30);not null;"`		//申请提交时间
	PreHash string		`gorm:"type:varchar(64);not null"`		//上一节点的哈希值
	Username string		`gorm:"type:varchar(20);not null"`		//用户名
	ApplyId string		`gorm:"type:varchar(255);not null"`		//申请人证件号码
	FileHash string		`gorm:"type:varchar(64);not null"`		//文件哈希值
	ApplyName string	`gorm:"type:varchar(90);not null"`		//申请人姓名
	AuthAccount string	`gorm:"type:varchar(25);not null"`		//审核者
	CurHash string		`gorm:"type:varchar(64);not null"`		//当前节点的哈希值
}

type AuthSession struct{
	TimeHash string 	`gorm:"type:varchar(64);not null;unique_index;primary_key"`	//时间戳的哈希值
	LastVisit string	`gorm:"type:varchar(30);not null"`	//最后一次访问的时间戳（精确到秒）
	Username string		`gorm:"type:varchar(40);not null"`	//当前session对应的用户信息
}

func getHash(path string) (status int, hash string) {
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		return -1,""		//打开文件出错，即文件不存在。
	} else {
		h1 := sha256.New()
		_, err := io.Copy(h1, file)
		if err == nil {
			hash := h1.Sum(nil)
			hashValue := hex.EncodeToString(hash)
			return 0, hashValue	//正常生成。
		} else {
			return -2, ""	//生成哈希值出错
		}
	}

}
var database,databaseERR = gorm.Open("mysql","admin:123456@(127.0.0.1:3306)/demo?charset=utf8mb4&parseTime=True&loc=Local")
//连接mysql数据库

func main(){
				if databaseERR != nil{
					panic(databaseERR)
				}
				defer database.Close()
				database.AutoMigrate(&User{})
				database.AutoMigrate(&Authority{})
				database.AutoMigrate(&Application{})
				database.AutoMigrate(&Chain{})
				database.AutoMigrate(&AuthSession{})

	blockchain = DemoChain.NewBlockchain()
	// 创建一个默认的路由引擎
	gin_logfile, _ := os.Create("./file/Gin_Demochain.log")	//将gin的日志保存在log文件中
	gin.DefaultWriter = io.MultiWriter(gin_logfile)
	server_logfile, _ := os.Create("./file/server.log")	//将日志保存在log文件中
	log.SetOutput(server_logfile)
	r := gin.Default()
	r.Static("/p", "./html/statics")
	r.LoadHTMLFiles(
		"./html/ERROR.html",
		"./html/examine.html",
		"./html/findMyApplication.html",
		"./html/findMyExamination.html",
		"./html/index.html",
		"./html/login.html",
		"./html/logout.html",
		"./html/register.html",
		"./html/startExamine.html",
		"./html/success.html",
		"./html/upload.html",
		"./html/uploadMyPEM.html")
	r.Use(Session("SHU"))
	// GET：请求方式；/hello：请求的路径
	// 当客户端以GET方法请求/hello路径时，会执行后面的匿名函数
	r.GET("/index", blockchainIndex)
	r.GET("/blockchain/get", authMiddleWare(),checkPermission(), blockchainGetHandler)
	r.GET("/blockchain/upload", authMiddleWare(),checkPermission(), startUpload)
	r.GET("/blockchain/examine", authMiddleWare(),checkPermission(), startExamine)
	r.GET("/blockchain/myapplication", authMiddleWare(),checkPermission(), findMyApplicaion)
	r.GET("/blockchain/myexamination", authMiddleWare(),checkPermission(), findMyExamination)
	r.GET("/blockchain/register", startRegister)
	r.GET("/blockchain/login", startLogin)
	r.GET("/blockchain/logout", authMiddleWare(),checkPermission(), startLogout)
	r.GET("/blockchain/uploadmypemfile", authMiddleWare(),checkPermission(), startUploadPemFile)
	r.POST("/examine", authMiddleWare(),checkPermission(), examine)
	r.POST("/logout", logout)
	r.POST("/login", login)
	r.POST("/register", register)
	r.POST("/upload", authMiddleWare(),checkPermission(), fileUpload)
	r.POST("/blockchain/dealexamine",authMiddleWare(),checkPermission(), dealExamine)
	r.POST("/uploadmypemfile", authMiddleWare(),checkPermission(), uploadPemFile)
	r.POST("/testmypemfile", authMiddleWare(),checkPermission(), testPemFile)
	r.GET("/blockchain/download",authMiddleWare(),checkPermission(), downloadPDF)
	r.GET("/downloadsignexe", authMiddleWare(), checkPermission(), signEXEDownload)//下载签名软件
	r.GET("/captcha", func(c *gin.Context) {
		Captcha(c, 4)
	})

	// 启动HTTP服务，默认在0.0.0.0:8080启动服务
	err :=r.Run(":8080")
	if err != nil {
		fmt.Println("启动HTTP服务失败：", err)
	}
}

func testPemFile(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="普通用户"{
		log.Println("【错误代码：102】",Group,"：",userName,"尝试测试pem文件操作，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有测试pem文件的需要！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		log.Println(Group,"：",userName,"正在进行测试pem文件操作。")
		privateHash := c.PostForm("priHash")
		path:=fmt.Sprintf("./uploadedfiles/pem/%s/%s",userName,privateHash)
		_, err := os.Stat(path)
		if os.IsNotExist(err) {	//如果文件不存在
			c.HTML(http.StatusBadRequest, "ERROR.html", gin.H{"errdata": "PEM文件未找到！", "errcode": 16, "website": "/blockchain/uploadmypemfile", "webName": "上传PEM文件"})
		} else{
			c.HTML(http.StatusOK, "success.html", gin.H{"data": "已找到PEM文件，无需上传！", "website": "/blockchain/upload", "webName": "上传页面"})
		}
	}
}

func startUploadPemFile(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="普通用户"{
		log.Println("【错误代码：13】",Group,"：",userName,"尝试上传pem文件操作，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "是普通用户，没有上传pem文件的需要！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		c.HTML(http.StatusOK, "uploadMyPEM.html", gin.H{"userName":userName,"Group":Group})
	}
}

func uploadPemFile(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="普通用户"{
		log.Println("【错误代码：102】",Group,"：",userName,"正在上传pem文件操作，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有上传pem文件的需要！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		log.Println(Group,"：",userName,"正在进行上传pem文件操作。")
		privateHash := c.PostForm("privateHash")	//获得表单中的私钥哈希值
		publicHash := c.PostForm("publicHash")		//获得表单中的公钥哈希值
		//传递公钥pem文件。
		pem, _ := c.FormFile("pem")
		thisPath := fmt.Sprintf("./uploadedfiles/pem/%s/%s", userName, privateHash)
		os.MkdirAll(thisPath, os.ModePerm)
		pemPath := fmt.Sprintf("./uploadedfiles/pem/%s/%s/%s", userName, privateHash, pem.Filename)
		// 上传PEM文件到指定的路径（路径包含用户名与对应的公钥哈希值）
		if pem.Filename == "public.pem" { //上传的是public.pem文件
			err := c.SaveUploadedFile(pem, pemPath)
			if err != nil {		//保存失败，报错
				c.HTML(http.StatusInternalServerError, "ERROR.html",gin.H{"errdata": "服务器端保存PEM文件失败！请联系网站管理员！", "errcode": -2,"website":"/blockchain/uploadmypemfile","webName":"上传PEM文件"})
			}
		} else {	//上传的不是public.pem文件，报错
			c.HTML(http.StatusInternalServerError, "ERROR.html",gin.H{"errdata": "上传的不是public.pem！", "errcode": 2,"website":"/blockchain/uploadmypemfile","webName":"上传PEM文件"})
			return
		}
		_, realPublicHash := getHash(pemPath)	//验证公钥哈希值
		if realPublicHash != publicHash { 		//公钥哈希值与用户上传的哈希值不同，文件已被篡改。
			_ = os.RemoveAll(thisPath)			//删除当前文件夹及其子文件
			userPath := "./uploadedfiles/"
			userPath += userName
			dir, _ := ioutil.ReadDir(userPath)	//检测该用户名是否有其余公钥哈希值上传记录。若有则保留用户名文件夹
			if len(dir) == 0 {
				_ = os.RemoveAll(userPath)		//若没有，删除用户名文件夹及其子文件
			}
			c.HTML(http.StatusInternalServerError, "ERROR.html", gin.H{"errdata": "PEM文件已被修改！请重新尝试提交。若多次提交均显示文件已被修改，请检查您的网络环境！", "errcode": 4, "website": "/blockchain/uploadmypemfile", "webName": "上传PEM文件"})
		}		//公钥哈希值与用户上传的哈希值相同。上传成功。
		c.HTML(http.StatusOK, "success.html", gin.H{"data": "上传PEM文件成功！", "website": "/blockchain/upload", "webName": "上传页面"})
	}
}

func findMyExamination(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="权力机构用户"{
		log.Println("【错误代码：13】",Group,"：",userName,"尝试查询审核记录操作，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有审核记录！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		log.Println(Group,"：",userName,"正在进行查询审核记录操作。")
		var application []Application
		result := database.Find(&application, "auth_account=?", userName)
		len := result.RowsAffected
		myExamination := application
		c.HTML(http.StatusOK, "findMyExamination.html", gin.H{"userName":userName,"Group":Group,"len":len,"myExamination":myExamination})
	}
}

func findMyApplicaion(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="普通用户"{
		log.Println("【错误代码：13】",Group,"：",userName,"尝试查询上传记录操作，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是权力机构用户，没有上传申请记录！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		log.Println(Group,"：",userName,"正在进行查询上传记录操作。")
		var application []Application
		result := database.Find(&application, "username=?", userName)
		len := result.RowsAffected
		myApplication := application
		c.HTML(http.StatusOK, "findMyApplication.html", gin.H{"userName":userName,"Group":Group,"len":len,"myApplication":myApplication})
	}
}

func downloadPDF(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	uptime := c.Query("uptime")
	normalUserName := c.Query("normalUserName")
	fileName := c.Query("fileName")
	if Group!="权力机构用户"{
		log.Println("【错误代码：102】",Group,"：",userName,"尝试下载",normalUserName,"/",uptime,"/",fileName,"，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有审核记录！", "errcode": 13,"website":"/index","webName":"主页"})
	} else {
		log.Println(Group,"：",userName,"正在进行下载",normalUserName,"/",uptime,"/",fileName,"操作。")
		c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", normalUserName+"-"+uptime+".pdf")) //fmt.Sprintf("attachment; filename=%s", filename)对下载的文件重命名
		c.Writer.Header().Add("Content-Type", "application/octet-stream")
		c.File("./uploadedfiles/" + normalUserName + "/" + uptime + "/" + fileName)
	}
}

func startExamine(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="权力机构用户"{
		log.Println("【错误代码：13】",Group,"：",userName,"尝试查询待审核列表操作，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有权限审核上传申请！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		//查“待审核”记录
		log.Println(Group,"：",userName,"正在进行查询待审核列表操作。")
		var application []Application
		result := database.Find(&application, "ver_status=? or (ver_status=? and auth_account=?)", "待审核","审核中",userName)
		len := result.RowsAffected
		appToBeExamined := application
		//选“待审核”记录
		c.HTML(http.StatusOK, "startExamine.html", gin.H{"userName":userName,"Group":Group,"len":len,"appToBeExamined":appToBeExamined})
	}
}

func examine(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	appId := c.PostForm("appId")	//选到了某个时间戳对应的记录详情
	if Group!="权力机构用户"{
		log.Println("【错误代码：102】",Group,"：",userName,"尝试开始审核第",appId,"号申请，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有权限审核上传申请！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		log.Println(Group,"：",userName,"开始审核第",appId,"号申请。")
		var application Application
		result := database.First(&application, "uptime=? and (ver_status=? or (ver_status=? and auth_account=?))", appId, "待审核","审核中",userName)
		if result.RowsAffected == 1{
			database.Model(&application).Update("ver_status", "审核中")		//访问这条申请，说明权力机构用户已经在处理这条请求了，将数据库中的申请状态改成审核中，
			database.Model(&application).Update("auth_account", userName)	//审核者改成当前账户名
			c.HTML(http.StatusOK,"examine.html",gin.H{
				"normalUserName":application.Username,
				"userName":userName,
				"Group":Group,
				"appToBeExamined":application,
				"uptime":appId,
				"fileName":application.FileName,
			})
		}else {	//找不到当前时间戳对应的请求或者请求的ver_status不是“待审核”
			c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "查询不到当前申请或当前申请已被其他权力机构账号处理", "errcode": 12,"website":"/blockchain/examine","webName":"待处理请求页面"})
		}
	}
}

func dealExamine(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	appId := c.PostForm("appId")	//选到了某个时间戳对应的记录详情
	var application Application
	if Group!="权力机构用户"{
		log.Println("【错误代码：102】",Group,"：",userName,"尝试审核第",appId,"号申请，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是普通用户，没有权限审核上传申请！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		log.Println(Group,"：",userName,"正在审核第",appId,"号申请。")
		result := database.Find(&application, "uptime=?", appId)
		if result.RowsAffected == 1{
			action := c.PostForm("status")
			words := c.PostForm("saySth")
			if action == "deny"	{//审核不通过
				database.Model(&application).Update("auth_time", time.Now().Format("2006-01-02 03:04:05"))
				database.Model(&application).Update("auth_account", userName)
				database.Model(&application).Update("auth_text", words)
				database.Model(&application).Update("ver_status", "审核不通过")
				c.HTML(http.StatusOK,"success.html",gin.H{"data":"设置“不通过“成功！","website":"/blockchain/examine","webName":"待处理请求页面"})
			} else if action == "accept" { //审核通过
				database.Model(&application).Update("auth_time", time.Now().Format("2006-01-02 03:04:05"))
				database.Model(&application).Update("auth_account", userName)
				database.Model(&application).Update("auth_text", words)
				database.Model(&application).Update("ver_status", "审核通过")

				applyTime := application.Uptime
				fileHash := application.FileHash
				authorUsername := application.Username
				author := application.ApplyName
				authorId := application.ApplyId
				authorityUsername := application.AuthAccount
				index, preHash, curHash, timestamp := blockchain.SendData(applyTime, authorId, fileHash, authorUsername, author, authorityUsername)
				chain := Chain{int(index), int(timestamp),applyTime,preHash,author,authorId,fileHash, authorUsername,authorityUsername,curHash}
				database.Create(&chain)
				c.HTML(http.StatusOK, "success.html", gin.H{"data": "设置“通过“成功！", "website": "/blockchain/examine", "webName": "待处理请求页面"})
			}
		}
	}
}

func logout(c *gin.Context) {
	sessionId, _ := c.Cookie("sessionId")
	var userName string
	var session AuthSession
	result := database.First(&session, "time_hash=?", sessionId)
	if result.RowsAffected == 1 { //找到了信息
		userName = session.Username
		log.Println("用户",userName,"现已离线。")
		userName1 := "[out]" + userName
		database.Model(&session).Update("username", userName1) //在session表中将用户的账号前加入[out]标识
		c.SetCookie("sessionId", "", 0, "", "", false, true)   //清除浏览器中的cookie
	}
	c.HTML(http.StatusOK,"success.html",gin.H{"data":"用户"+userName+"退出登录成功！","website":"/index","webName":"主页"})
}

func startLogout(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	log.Println("用户",userName,"正在退出登录。")
	c.HTML(http.StatusOK, "logout.html", gin.H{"userName":userName,"Group":Group})
}

func startLogin(c *gin.Context){
	sessionId, err := c.Cookie("sessionId")
	if err == nil { //已登录
		var session AuthSession
		result := database.First(&session, "time_hash=?", sessionId)
		if result.RowsAffected == 1 { //找到了信息
			log.Println("【错误代码：8】","用户",session.Username,"正在重复登录，被驳回。")
			c.HTML(http.StatusForbidden, "ERROR.html", gin.H{"errdata": "已登录，请勿重复登录", "errcode": 8,"website":"/index","webName":"主页"})
			return
		}
	}
	log.Println("有用户即将登录。")
	c.HTML(http.StatusOK, "login.html", nil)
}
func startRegister(c *gin.Context){
	sessionId, err := c.Cookie("sessionId")
	if err == nil { //已登录
		var session AuthSession
		result := database.First(&session, "time_hash=?", sessionId)
		if result.RowsAffected == 1 { //找到了信息
			log.Println("【错误代码：8】","用户",session.Username,"正在注册，被驳回。")
			c.HTML(http.StatusForbidden, "ERROR.html", gin.H{"errdata": "已登录，请勿在登录状态注册账号", "errcode": 8,"website":"/index","webName":"主页"})
			return
		}
	}
	log.Println("有新的用户正在注册。")
	c.HTML(http.StatusOK, "register.html", nil)
}


func register(c *gin.Context){
	userName := c.PostForm("username")
	password := c.PostForm("password")
	value := c.PostForm("verCode")
	if CaptchaVerify(c, value) {	//验证码通过
		data := User{userName, password}
		err := database.Create(&data)
		strErr := fmt.Sprintf("%v", err.Error)
		if strErr != "<nil>" {
			log.Println("【错误代码：7】","新用户注册失败，失败原因：",strErr)
			c.HTML(http.StatusForbidden, "ERROR.html", gin.H{"errcode":"7","errdata":"注册失败！"+strErr,"website":"/blockchain/register","webName":"注册页面"})
		}else {
			log.Println("新用户：",userName," 注册成功！")
			c.HTML(http.StatusOK,"success.html",gin.H{"data":"注册成功！","website":"/blockchain/login","webName":"登录页面"})
		}
	} else {	//验证码错误
		log.Println("【错误代码：15】","有正在注册的用户输错了验证码...")
		c.HTML(http.StatusBadRequest, "ERROR.html", gin.H{"errcode": "15", "errdata": "验证码错误！", "website": "/blockchain/login", "webName": "登录页面"})
	}
}

func login(c *gin.Context){
	userName := c.PostForm("username")
	password := c.PostForm("password")	//获取表单提交的账户和密码
	value := c.PostForm("verCode")
	if CaptchaVerify(c, value) {	//验证码正确
		var user User
		var auth Authority
		result := database.First(&user, "username=?", userName)
		if result.RowsAffected == 1 {	//只找到一条数据，用户名存在，比对密码
			if password == user.Passwords{	//密码比对通过
				log.Println("普通用户：",userName," 登录成功！")
				var session []AuthSession	//寻找在数据库里是否有失效的cookie（指的是用户由于关闭了浏览器，已经没有sessionId了）
				result := database.Find(&session, "username=? or username=?", userName,"[out]"+userName)
				if result.RowsAffected != 0 {	//本地没有cookie，需要申请新的cookie时，删除以前保留在服务器中的cookie
					database.Delete(&session)
				}

				curTime := time.Now()
				nanoCurTime := curTime.UnixNano()	//获得当前时间（纳秒）
				sTime := curTime.Format("2006-01-02 15:04:05")
				strTime := fmt.Sprintf("%d", nanoCurTime)	//时间变为字符串
				tempHash := sha256.Sum256([]byte(strTime))
				timeHash := hex.EncodeToString(tempHash[:])		//计算时间哈希
				data := AuthSession{timeHash, sTime, userName}
				database.Create(&data)		//在authSession数据库加入一条信息
				http.SetCookie(c.Writer, &http.Cookie{
					Name:     "sessionId",
					Value:    timeHash,
					Path:     "/",
					Domain:   "",
					SameSite: http.SameSiteLaxMode,
					Secure:   false,
					HttpOnly: true,
				})
				c.Redirect(http.StatusMovedPermanently, "http://36b1c95548.qicp.vip/index")
				//设置一条 key为sessionId，值为当前时间哈希值，持续时间为关闭浏览器失效的cookie
			}else {		//普通用户——账户密码不匹配
				log.Println("【错误代码：101】","普通用户：",userName," 账号密码不匹配，登录失败！")
				c.HTML(http.StatusBadRequest,"ERROR.html",gin.H{"errcode":"11","errdata":"登录失败！","website":"/blockchain/login","webName":"登录页面"})
			}
		} else {	//不是普通用户，到权力机构表里找一找
			result = database.First(&auth, "username=?", userName)
			if result.RowsAffected == 1 { //只找到一条数据，用户名存在，比对密码
				if password == auth.Passwords { //密码比对通过
					log.Println("权力机构用户：",userName," 登录成功！")
					var session []AuthSession //寻找在数据库里是否有失效的cookie（指的是用户由于关闭了浏览器，已经没有sessionId了）
					result := database.Find(&session, "username=? or username=?", userName, "[out]"+userName)
					if result.RowsAffected != 0 { //本地没有cookie，需要申请新的cookie时，删除以前保留在服务器中的cookie
						database.Delete(&session)
					}

					curTime := time.Now()
					nanoCurTime := curTime.UnixNano() //获得当前时间（纳秒）
					sTime := curTime.Format("2006-01-02 15:04:05")
					strTime := fmt.Sprintf("%d", nanoCurTime) //时间变为字符串
					tempHash := sha256.Sum256([]byte(strTime))
					timeHash := hex.EncodeToString(tempHash[:]) //计算时间哈希
					data := AuthSession{timeHash, sTime, userName}
					database.Create(&data) //在authSession数据库加入一条信息
					http.SetCookie(c.Writer, &http.Cookie{
						Name:     "sessionId",
						Value:    timeHash,
						Path:     "/",
						Domain:   "",
						SameSite: http.SameSiteLaxMode,
						Secure:   false,
						HttpOnly: true,
					})
					c.Redirect(http.StatusMovedPermanently, "http://36b1c95548.qicp.vip/index")
					//设置一条 key为sessionId，值为当前时间哈希值，持续时间为关闭浏览器失效的cookie
				} else {	//权力机构——账户密码不匹配
					log.Println("【错误代码：101】","权力机构用户：",userName," 账号密码不匹配，登录失败！")
					c.HTML(http.StatusBadRequest, "ERROR.html", gin.H{"errcode": "11", "errdata": "登录失败！", "website": "/blockchain/login", "webName": "登录页面"})
				}
			}else {		//不存在该用户名
				log.Println("【错误代码：14】","有人正用不存在的用户名：",userName," 进行登录，被驳回！")
				c.HTML(http.StatusBadRequest, "ERROR.html", gin.H{"errcode": "14", "errdata": "用户名不存在！", "website": "/blockchain/login", "webName": "登录页面"})
			}
		}
	} else {	//验证码错误
		log.Println("【错误代码：15】","有正在登录的用户输错了验证码...")
		c.HTML(http.StatusBadRequest, "ERROR.html", gin.H{"errcode": "15", "errdata": "验证码错误！", "website": "/blockchain/login", "webName": "登录页面"})
	}
}

func checkPermission() gin.HandlerFunc{
	return func(c *gin.Context) {
		userName := c.MustGet("userName").(string)
		var user User
		result := database.First(&user, "username=?", userName)
		if result.RowsAffected == 1 {
			c.Set("userName",user.Username)
			c.Set("Group","普通用户")
		} else {
			var auth Authority
			result := database.First(&auth, "username=?", userName)
			if result.RowsAffected == 1 {
				c.Set("userName",auth.Username)
				c.Set("Group","权力机构用户")
			} else {
				log.Println("【错误代码：103】","检测到疑似非法用户！")
				c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "非法用户！", "errcode": 0,"website":"/index","webName":"主页"})
				c.Abort()
			}
		}
	}
}
func authMiddleWare() gin.HandlerFunc {		//检查cookie
	return func(c *gin.Context) {
		sessionId, err := c.Cookie("sessionId")
		if err == nil {
			var session AuthSession
			result := database.First(&session, "time_hash=?", sessionId)
			if result.RowsAffected == 1 {		//找到了信息
				sTime := time.Now().Format("2006-01-02 15:04:05")
				database.Model(&session).Update("last_visit", sTime)		//用一次session，更新一次时间。
				c.Set("userName",session.Username)
				c.Next()
				return
			}
		}
		// 返回错误
		c.HTML(http.StatusUnauthorized, "ERROR.html", gin.H{"errdata":"未登录","errcode":9,"website":"/blockchain/login","webName":"登录页面"})
		c.Abort()
		return
	}
}









func blockchainIndex(c *gin.Context){
	sessionId, err := c.Cookie("sessionId")
	var userName, Group string
	var session AuthSession
	if err == nil {
		result := database.First(&session, "time_hash=?", sessionId)
		if result.RowsAffected == 1 {		//找到了信息
			userName = session.Username
			sTime := time.Now().Format("2006-01-02 15:04:05")
			database.Model(&session).Update("last_visit", sTime)		//用一次session，更新一次时间。
		}
	}
	if strings.HasPrefix(userName, "[out]") || userName==""{
		userName = "未登录"
	}
	var user User
	result := database.First(&user, "username=?", userName)
	if result.RowsAffected == 1 {
		Group = "普通用户"
	} else {
		var auth Authority
		result := database.First(&auth, "username=?", userName)
		if result.RowsAffected == 1 {
			Group = "权力机构用户"
		} else {
			Group = "未登录"
		}
	}
	log.Println(Group,"：",userName," 正在访问主页。")
	c.HTML(http.StatusOK, "index.html", gin.H{"userName":userName,"Group":Group})
}

func startUpload(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="普通用户"{
		log.Println("【错误代码：13】",Group,"：",userName,"尝试上传申请，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是权力机构用户，没有权限上传申请！", "errcode": 13,"website":"/index","webName":"主页"})
	} else{
		nanoCurTime := time.Now().UnixNano()	//获取当前时间（精确到纳秒）
		nanoCurTime = nanoCurTime % 1000000000000	//选取差异较大的部分
		randStr := ""
		for nanoCurTime!=0 {
			tempNum := nanoCurTime % 100 % 78
			tempRune := rune(tempNum + 48)		//随机值从ASCII 48（0）取到125（}）
			randStr += string(tempRune)
			nanoCurTime = nanoCurTime / 100
		}
		log.Println(Group,"：",userName,"开始上传申请。")
		c.HTML(http.StatusOK, "upload.html", gin.H{"userName":userName,"Group":Group,"randStr":randStr})
	}
}

func fileUpload(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	if Group!="普通用户"{
		log.Println("【错误代码：102】",Group,"：",userName,"正在尝试上传申请，被驳回。")
		c.HTML(http.StatusBadRequest, "ERROR.html",gin.H{"errdata": "您是权力机构用户，没有权限上传申请！", "errcode": 13,"website":"/index","webName":"主页"})
	} else {
		nanoCurTime := time.Now().UnixNano()        //获取当前时间（精确到纳秒）
		timeStamp := fmt.Sprintf("%d", nanoCurTime) //时间变为字符串
		randStr := c.PostForm("randStr")
		name := c.PostForm("name") //姓名
		id := c.PostForm("id")
		userName := c.PostForm("userName") //账号
		var errdata string
		var httpcode, errcode int
		var data Application
		var user User
		database.First(&user, "username=?", userName)
		password := user.Passwords //密码（存在数据库中的SHA256密码）
		pdfHash := c.PostForm("pdfHash")
		privateHash := c.PostForm("PrivateHash")
		sign := c.PostForm("sign")
		verificationCode := c.PostForm("verificationCode")
		//传递pdf文件。
				pdf,_ := c.FormFile("pdf")
		log.Println(userName, "上传了文件", pdf.Filename)
		thisPath := fmt.Sprintf("./uploadedfiles/%s/%s", userName, timeStamp)
		os.MkdirAll(thisPath, os.ModePerm)
		pdfPath := fmt.Sprintf("./uploadedfiles/%s/%s/%s", userName, timeStamp, pdf.Filename)
		pemPath := fmt.Sprintf("./uploadedfiles/pem/%s/%s/public.pem", userName, privateHash)
		var realPdfHash string
		// 上传PDF文件到指定的目录
		if path2.Ext(pdfPath) == ".pdf" { //上传的是pdf格式文件
			err := c.SaveUploadedFile(pdf, pdfPath)
			if err != nil {
				httpcode = 500
				errcode = -1
				errdata = "服务器端保存PDF文件失败！请联系网站管理员！"
				goto FAIL
			}
		} else {
			httpcode = 500
			errcode = 1
			errdata = "上传的不是PDF文件！"
			goto FAIL
		}
		_, realPdfHash = getHash(pdfPath)
		//每收到一次上传请求就进行一次检验。
		//检测文件是否上传成功与是否未被篡改
		if realPdfHash != pdfHash { //文件哈希值与用户上传的哈希值不同，文件已被篡改。
			httpcode = 500
			errcode = 3
			errdata = "PDF文件已被修改！请重新尝试提交。若多次提交均显示文件已被修改，请检查您的网络环境！"
			goto FAIL
		} else { //PDF文件没问题，检测验证码是否匹配
			var total string
			total = pdfHash + " -#@#- " + name + " -#@#- " + id + " -#@#- " + userName + " -#@#- " + password + " -#@#- " + privateHash + " -#@#- " + sign + " -#@#- " + randStr
			//此处，password（账号密码【SHA256】）都是从数据库拿来的；pdfHash和pemHash前面已经验证过，所以直接用用户拿来的；userName（账号）、id（身份证）、Name、sign是从表单获取的。
			tempHash1 := sha256.Sum256([]byte(total))
			hash1 := hex.EncodeToString(tempHash1[:])
			hash1 += password
			tempHash2 := sha256.Sum256([]byte(hash1))
			hash2 := hex.EncodeToString(tempHash2[:])
			if hash2 != verificationCode { //哈希不一致，内容已被篡改。
				httpcode = 500
				errcode = 5
				errdata = "验证码验证失败！请检查上传的字符串中是否包含空格；生成验证码时是否输入正确。若确认无误但多次出现该错误信息，请留意您的网络环境！"
				goto FAIL
			} else { //所有信息未被篡改，最后验证签名。
				data := pdfHash + " -&@&- " + name + " -&@&- " + id
				piece1 := sha256.Sum256([]byte(data)) //算原话的哈希
				str1 := hex.EncodeToString(piece1[:]) //算好保存为字符串
				err := DemoChain.RSAVerify([]byte(str1), sign, pemPath)
				if err != nil {
					httpcode = 500
					errcode = 6
					errdata = "签名信息验证失败！请检查是否上传了正确的公钥文件！"
					goto FAIL
				} else { //所有验证通过，该条记录将被保存。
					goto SUCCESS
				}
			}
		}
	FAIL: //所有上传时的异常情况在这里处理
		log.Println("【错误代码：",errcode,"】",Group,"：",userName,"上传申请失败，失败原因：",errdata)
		data = Application{timeStamp, userName, name, id, pdfHash, pdf.Filename, "上传失败", "", "", "", ""}
		database.Create(&data)
		c.HTML(httpcode, "ERROR.html", gin.H{"errcode": errcode, "errdata": errdata, "website": "/blockchain/upload", "webName": "上传页面"})
		deleteFile(thisPath, id)
		return
	SUCCESS:
		result := database.Where("file_hash = ? and (ver_status = ? or ver_status = ? or ver_status = ?)", pdfHash, "待审核", "审核中", "审核通过").Find(&data) //找是否已经提交过同一PDF的申请，处于待审核或审核通过状态
		{
			if result.RowsAffected != 0 {
				log.Println("【错误代码：10】",Group,"：",userName,"重复提交了文件哈希值为",data.FileHash,"的申请，被驳回。")
				c.HTML(http.StatusForbidden, "ERROR.html", gin.H{"errcode": errcode, "errdata": "已提交过相同文件的申请，处于待审核或审核通过状态！", "website": "/blockchain/myapplication", "webName": "个人申请记录页面"})
				return
			}
		}
		data = Application{timeStamp, userName, name, id, pdfHash, pdf.Filename, "上传成功", "待审核", "", "", ""}
		database.Create(&data)
		log.Println(Group,"：",userName,"成功提交了文件哈希值为",data.FileHash,"的申请。")
		c.HTML(http.StatusOK, "success.html", gin.H{"data": "请求上传成功！", "website": "/blockchain/myapplication", "webName": "个人申请记录页面"})
		return
	}
}

func blockchainGetHandler(c *gin.Context) {
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	bytes, err := json.Marshal(blockchain)
	if err != nil {
		strErr := fmt.Sprintf("%v", err)
		log.Println("【错误代码：-3】",Group,"：",userName,"读取区块链时出现错误：",strErr)
		c.HTML(http.StatusInternalServerError, "ERROR.html",gin.H{"errdata": "读取区块链失败："+strErr, "errcode": -3,"website":"/index","webName":"主页"})
		return
	}
	log.Println(Group,"：",userName,"正在读取区块链。")
	c.JSON(http.StatusOK, string(bytes))
}



func signEXEDownload(c *gin.Context){
	userName := c.MustGet("userName").(string)
	Group := c.MustGet("Group").(string)
	log.Println(Group,"：",userName,"正在下载签名软件。")
	c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", "签名软件.exe"))//fmt.Sprintf("attachment; filename=%s", filename)对下载的文件重命名
	c.Writer.Header().Add("Content-Type", "application/octet-stream")
	c.File("./file/sign.exe")
}


func deleteFile(thisPath string, id string){
	_ = os.RemoveAll(thisPath)
	userPath := "./uploadedfiles/"
	userPath += id
	dir, _ := ioutil.ReadDir(userPath)
	if len(dir) == 0 {
		_ = os.RemoveAll(userPath)
	}
}

//------------------------------------------------以下为生成图形验证码。--------------------------------------------------------//
func Session(keyPairs string) gin.HandlerFunc {
	store := SessionConfig()
	return sessions.Sessions(keyPairs, store)
}
func SessionConfig() sessions.Store {
	sessionMaxAge := 600
	sessionSecret := "SHU"
	var store sessions.Store
	store = cookie.NewStore([]byte(sessionSecret))
	store.Options(sessions.Options{
		MaxAge: sessionMaxAge, //seconds
		Path:   "/",
	})
	return store
}

func Captcha(c *gin.Context, length ...int) {
	l := captcha.DefaultLen
	w, h := 107, 36
	if len(length) == 1 {
		l = length[0]
	}
	if len(length) == 2 {
		w = length[1]
	}
	if len(length) == 3 {
		h = length[2]
	}
	captchaId := captcha.NewLen(l)
	session := sessions.Default(c)
	session.Set("captcha", captchaId)
	_ = session.Save()
	_ = Serve(c.Writer, c.Request, captchaId, ".png", "zh", false, w, h)
}
func CaptchaVerify(c *gin.Context, code string) bool {
	session := sessions.Default(c)
	if captchaId := session.Get("captcha"); captchaId != nil {
		session.Delete("captcha")
		_ = session.Save()
		if captcha.VerifyString(captchaId.(string), code) {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}
func Serve(w http.ResponseWriter, r *http.Request, id, ext, lang string, download bool, width, height int) error {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	var content bytes.Buffer
	switch ext {
	case ".png":
		w.Header().Set("Content-Type", "image/png")
		_ = captcha.WriteImage(&content, id, width, height)
	case ".wav":
		w.Header().Set("Content-Type", "audio/x-wav")
		_ = captcha.WriteAudio(&content, id, lang)
	default:
		return captcha.ErrNotFound
	}

	if download {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeContent(w, r, id+ext, time.Time{}, bytes.NewReader(content.Bytes()))
	return nil
}
