package main

import (
	"fmt"
	"net"
	"os"
	"log"
	"bytes"
	"./dhexchange"
	"encoding/json"
	"encoding/binary"
	"time"
	"bufio"
)

var G,P dhexchange.Uint128
var pri_key dhexchange.Uint128
var pub_key dhexchange.Uint128
var another_pub_key dhexchange.Uint128
var secret_key dhexchange.Uint128

//这是处理报文的函数
//报文格式如下：t_type：报文类型， G：参数G， P：参数P， pub_key：报文中传输的公钥，ciphertext：密文，msg：附加信息
//报文交互：以下序号为t_type
//
//					1：客户发送给服务器的报文，请求P,G
//					2：服务器发送给客户端的报文，回复P，G
//					3：客户端回复服务器报文，回复客户端的公钥
//					4: 服务器回复客户端报文，回复服务器的公钥
//					至此,服务器和客户端协商密钥完成
//					5：使用协商密钥，AES128加密算法进行密文传输


//客户端发送报文函数
func sender(conn net.Conn, i int){
	var req_msg dhexchange.DH_pac
	
	if i==1{//request G and P
		G.Str_16 = make([]byte,16)
		P.Str_16 = make([]byte,16)
		req_msg.T_type = 1
		req_msg.Msg = "request for G P"
		fmt.Println("client request for constant G and P....")
	}
	if i==3{//send public key to server
		req_msg.T_type = 3
		req_msg.Msg = "send public key to server"
		req_msg.Pub_key = pub_key.Str_16
		fmt.Println("client send public key:")
		dhexchange.Print_16(pub_key)
		fmt.Println(" ")
	}
	if i==5{//send ciphertext
		req_msg.T_type = 5
		
		readbuf := bufio.NewReader(os.Stdin)
		fmt.Println("input plaintext you want to send: ")
		plaintext, hasmore,errx :=readbuf.ReadLine()
	
		if errx != nil || hasmore == true{
			os.Exit(1)
		}
		fmt.Println("plaintext is: ")
		fmt.Println(string(plaintext))
		plaintext1 := []byte(string(plaintext))
		fmt.Println("ciphertext is: ")
		ciphertext,_ := dhexchange.AesEncrypt(plaintext1,secret_key.Str_16)
		fmt.Println(string(ciphertext))
		req_msg.Ciphermsg = []byte(string(ciphertext))
		req_msg.Msg = "send ciphertext"
	}
	b,err := json.Marshal(req_msg)
	if err != nil{
		fmt.Println("error: ",err)
	}
	conn.Write(b)
	fmt.Println("send over")
}

//客户端接受保温函数
func reader(conn net.Conn){
	buffer := make([]byte,1024)
	n,err := conn.Read(buffer)
	if err != nil{
		Log(conn.RemoteAddr().String()," connection error: ", err)
		return 
	}
	var get_msg dhexchange.DH_pac
	
	err = json.Unmarshal(buffer[:n],&get_msg)
	if err != nil{
		fmt.Println("error: ", err)
	}
	if get_msg.T_type == 2{//G P get
		P.Str_16 = []byte(get_msg.P)
		G.Str_16 = []byte(get_msg.G)
		
		
		buff1 := bytes.NewBuffer(G.Str_16[:8])
		binary.Read(buff1,binary.BigEndian,&(G.High))
		buff2 := bytes.NewBuffer(G.Str_16[8:16])
		binary.Read(buff2,binary.BigEndian,&(G.Low))
		buff3 := bytes.NewBuffer(P.Str_16[:8])
		binary.Read(buff3,binary.BigEndian,&(P.High))
		buff4 := bytes.NewBuffer(P.Str_16[8:16])
		binary.Read(buff4,binary.BigEndian,&(P.Low))
		
		pub_key,pri_key = dhexchange.DH_generate_key_pair(G,P)
		
		fmt.Println("client get G: ")
		dhexchange.Print_16(G)
		fmt.Println("client get P: ")
		dhexchange.Print_16(P)
		fmt.Println(" ")
		
	}
	if get_msg.T_type == 4{//get pub_key
		another_pub_key.Str_16 = []byte(get_msg.Pub_key)
		buff1 := bytes.NewBuffer(another_pub_key.Str_16[:8])
		binary.Read(buff1,binary.BigEndian,&(another_pub_key.High))
		buff2 := bytes.NewBuffer(another_pub_key.Str_16[8:16])
		binary.Read(buff2,binary.BigEndian,&(another_pub_key.Low))
		fmt.Println("client get server's public key: ")
		dhexchange.Print_16(another_pub_key)
		fmt.Println(" ")
		secret_key = dhexchange.DH_generate_key_secret(G,P,pri_key,another_pub_key)
		fmt.Println("client create secret key: ")
		dhexchange.Print_16(secret_key)
		fmt.Println(" ")
	}
	//Log(conn.RemoteAddr().String()," receive data string:\n",string(buffer[:n]))
}
func main(){
	server := "localhost:8001"
	tcpAddr,err := net.ResolveTCPAddr("tcp4",server)
	if err != nil{
		fmt.Fprintf(os.Stderr,"Fatal erro: %s", err.Error())
		os.Exit(1)
	}
	
	conn,err := net.DialTCP("tcp",nil,tcpAddr)
	if err != nil{
		fmt.Fprintf(os.Stderr,"Fatal erro: %s", err.Error())
		os.Exit(1)
	}
	
	fmt.Println("connect success")
	sender(conn,1)
	reader(conn)
	time.Sleep(3*time.Second)
	sender(conn,3)
	reader(conn)
	time.Sleep(3*time.Second)
	fmt.Println("Now the secret key :")
	dhexchange.Print_16(secret_key)
	sender(conn,5)
	
	
	
	
}

func Log(v ...interface{}){
	log.Println(v...)
}