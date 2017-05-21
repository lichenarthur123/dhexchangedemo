package main
import (
	"fmt"
	"net"
	"log"
	"os"
	"./dhexchange"
	"bytes"
	"encoding/binary"
	"encoding/json"
)
var G,P dhexchange.Uint128
var pri_key dhexchange.Uint128
var pub_key dhexchange.Uint128
var another_pub_key dhexchange.Uint128
var secret_key dhexchange.Uint128
var dh_key_length = 16

func main(){

	G.Str_16 = make([]byte,dh_key_length)
	P.Str_16 = make([]byte,dh_key_length)
	
	netListen, err := net.Listen("tcp","localhost:8001")
	CheckError(err)
	defer netListen.Close()
	
	Log("Waiting for clients")
	
	for{
		conn,err := netListen.Accept()
		if err != nil {
			continue
		}
		
		Log(conn.RemoteAddr().String()," tcp connect success")
		handleConnection(conn)
	}
}
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
func handleConnection(conn net.Conn){
	buffer := make([]byte,1024)
	for{
		n,err := conn.Read(buffer)
		if err != nil{
			Log(conn.RemoteAddr().String()," connection error: ", err)
			return 
		}
		//Log(conn.RemoteAddr().String()," receive data string:\n",string(buffer[:n]))
		
		var get_msg dhexchange.DH_pac
		err = json.Unmarshal(buffer[:n],&get_msg)
		if err != nil{
			fmt.Println("error: ", err)
		}
		var req_msg dhexchange.DH_pac
		if get_msg.T_type == 1{//send P G
			G,P = dhexchange.DH_generate_G_P()
			req_msg.T_type = 2
			req_msg.G = G.Str_16
			req_msg.P = P.Str_16
			req_msg.Msg = "send P G"
			fmt.Println("server send P: ")
			dhexchange.Print_16(P)
			fmt.Println("server send G: ")
			dhexchange.Print_16(G)
			fmt.Println(" ")
			b,err := json.Marshal(req_msg)
			if err != nil{
				fmt.Println("error: ",err)
			}
			conn.Write(b)
			//Log(conn.RemoteAddr().String()," send data string:\n",string(b))
			
		}
		if get_msg.T_type == 3{//get pub_key and send pub_key
		
			pub_key,pri_key = dhexchange.DH_generate_key_pair(G,P)
			another_pub_key.Str_16 = []byte(get_msg.Pub_key)
			fmt.Println("server get client's public key: ")
			dhexchange.Print_16(another_pub_key)
			fmt.Println(" ")
			fmt.Println("server send public key: ")
			dhexchange.Print_16(pub_key)
			fmt.Println(" ")
			buff1 := bytes.NewBuffer(another_pub_key.Str_16[:8])
			binary.Read(buff1,binary.BigEndian,&(another_pub_key.High))
			buff2 := bytes.NewBuffer(another_pub_key.Str_16[8:16])
			binary.Read(buff2,binary.BigEndian,&(another_pub_key.Low))
			secret_key = dhexchange.DH_generate_key_secret(G,P,pri_key,another_pub_key)
			
			fmt.Println("server create secret key: ")
			dhexchange.Print_16(secret_key)
			fmt.Println(" ")
			
			
			req_msg.T_type = 4
			req_msg.Pub_key = pub_key.Str_16
			req_msg.Msg = "send  public key"
			
			b,err := json.Marshal(req_msg)
			if err != nil{
				fmt.Println("error: ",err)
			}
			conn.Write(b)
			//Log(conn.RemoteAddr().String()," send data string:\n",string(b))
		}
		if get_msg.T_type==5{//get ciphertext
			plaintext2,_ := dhexchange.AesDecrypt(get_msg.Ciphermsg,secret_key.Str_16)
			fmt.Println("plaintext is: ")
			fmt.Println(string(plaintext2))
			fmt.Println(" ")
		}
	}
}

func Log(v ...interface{}){
	log.Println(v...)
}

func CheckError(err error){
	if err != nil{
		fmt.Fprintf(os.Stderr,"Fatal error: %s",err.Error())
		os.Exit(1)
	}
}