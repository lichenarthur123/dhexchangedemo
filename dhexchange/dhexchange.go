//dh库文件

package dhexchange

import (
	"fmt"
	"crypto/rand"
	"bytes"
	"encoding/binary"
	"strconv"
	"crypto/cipher"
	"crypto/aes"
)
var dh_key_length = 16

type Uint128 struct{
	Low uint64
	High uint64
	Str_16 []byte
}

type DH_pac struct{
	T_type int
	G []byte
	P []byte
	Pub_key []byte
	Ciphermsg []byte
	Msg string
}
//测试输出函数
func Print_16(a Uint128) {
	buffer := new(bytes.Buffer)
	for _, b := range a.Str_16[:dh_key_length]{
		s := strconv.FormatInt(int64(b&0xff),16)
		if len(s)==1{
			//fmt.Println("0")
			buffer.WriteString("0")
		}
		buffer.WriteString(s)
	}
	fmt.Println(buffer.String())
} 
//P G 生成函数
func DH_generate_G_P() (g,p Uint128){
	p.Str_16 = make([]byte, dh_key_length)
	for i,_ := range p.Str_16[:dh_key_length]{
		p.Str_16[i] = 0xff
	}
	p.Str_16[dh_key_length-1] = 0x61
	buff1 := bytes.NewBuffer(p.Str_16[:8])
	binary.Read(buff1,binary.BigEndian,&(p.High))
	buff2 := bytes.NewBuffer(p.Str_16[8:16])
	binary.Read(buff2,binary.BigEndian,&(p.Low))
	
	g.Str_16 = make([]byte, dh_key_length)
	g.High = 0
	g.Low = 5
	
	binary.BigEndian.PutUint64(g.Str_16[:8], g.High)
	binary.BigEndian.PutUint64(g.Str_16[8:16],g.Low)
	
	
	return 
}
//以下为大数计算部分 
func compare_128(a,b Uint128) (r int){
	if a.High > b.High{
		return 1
	}
	if a.High < b.High{
		return -1
	}
	if a.Low > b.Low{
		return 1
	}
	if a.Low < b.Low{
		return -1
	}
	return 0
}

func is_odd_128(a Uint128) (r uint64){
	return (a.Low&1)
}

func lshift_128(a *Uint128){
	var t uint64
	t = ((*a).Low >> 63)&1
	(*a).High = ((*a).High << 1)|t
	(*a).Low = (*a).Low << 1
}

func rshift_128(a *Uint128){
	var t uint64
	t = ((*a).High & 1 ) << 63
	(*a).Low = ((*a).Low >> 1)|t
	(*a).High = (*a).High >> 1
}

func add_128_i(r *Uint128, a Uint128, b uint64){
	var overflow uint64
	overflow=0
	var Low uint64
	Low = a.Low+b
	if Low < a.Low || Low < b{
		overflow = 1
	}
	(*r).Low = Low
	(*r).High = a.High+overflow
}

func add_128(r *Uint128, a, b Uint128){
	var overflow uint64
	overflow=0
	var Low uint64
	Low = a.Low+b.Low
	if Low < a.Low || Low < b.Low{
		overflow = 1
	}
	(*r).Low = Low
	(*r).High = a.High+overflow+b.High
}

func sub_128(t *Uint128, a, b Uint128){
	var invert_b Uint128 
	invert_b.Low = ^b.Low
	invert_b.High = ^b.High
	add_128_i(&invert_b,invert_b,1)
	add_128(t,a,invert_b)
}

func powmod(pub_key *Uint128, G, pri_key, P Uint128){
	if(compare_128(G,P)>0){
		sub_128(&G,G,P)
		fmt.Println("!!!!")
	}
	powmod_r(pub_key, G, pri_key, P)
}

func mulpow(r *Uint128, a, b, c Uint128) {
	var t,double_a,p_a Uint128;
	var invert_p Uint128
	invert_p.Low = 159
	invert_p.High = 0
	
	(*r).Low = 0
	(*r).High = 0
	
	for{
		if b.Low ==0&&b.High==0{
			break;
			//fmt.Println("asd")
		}
		//fmt.Println("asd")
		if is_odd_128(b)==1{
			sub_128(&t,c,a)
			
			if compare_128(*r, t)>=0 {
				sub_128(r,*r,t)
			} else {
				add_128(r,*r,a)
			}
		}
		double_a = a
		lshift_128(&double_a)
		
		sub_128(&p_a,c,a)
		
		if compare_128(a,p_a)>=0{
			add_128(&a,double_a,invert_p)
		} else{
			a = double_a
		}
		rshift_128(&b)
	}
}

func powmod_r(r *Uint128, a,b,c Uint128){
	var t,half_b Uint128
	half_b = b
	
	
	if b.High == 0 && b.Low == 1{
		(*r) = a
		return
	}
	rshift_128(&half_b)
	
	powmod_r(&t,a,half_b,c)
	mulpow(&t,t,t,c)
	if is_odd_128(b)==1{
		mulpow(&t,t,a,c)
	}
	*r = t
}
//以上为大数计算部分

//公私钥对生成函数
func DH_generate_key_pair(G,P Uint128) (pub_key, pri_key Uint128){
	pri_key.Str_16 = make([]byte, dh_key_length)
	
	_,err := rand.Read(pri_key.Str_16)
	if err != nil {
		fmt.Println("error:",err)
	}
	buff1 := bytes.NewBuffer(pri_key.Str_16[:8])
	binary.Read(buff1,binary.BigEndian,&(pri_key.High))
	buff2 := bytes.NewBuffer(pri_key.Str_16[8:16])
	binary.Read(buff2,binary.BigEndian,&(pri_key.Low))
	
	pub_key.Str_16 = make([]byte, dh_key_length)
	pub_key.Low = 0
	pub_key.High = 0
	
	powmod(&pub_key, G, pri_key, P)
	
	pub_key.Str_16 = make([]byte,16)
	binary.BigEndian.PutUint64(pub_key.Str_16[:8], pub_key.High)
	binary.BigEndian.PutUint64(pub_key.Str_16[8:16],pub_key.Low)
	
	return
}

//共享密钥生成函数
func DH_generate_key_secret(G,P,pri_key,pub_key Uint128) (secret_key Uint128){
	secret_key.Str_16 = make([]byte, dh_key_length)
	powmod(&secret_key,pub_key,pri_key,P)
	
	binary.BigEndian.PutUint64(secret_key.Str_16[:8], secret_key.High)
	binary.BigEndian.PutUint64(secret_key.Str_16[8:16],secret_key.Low)
	return
}


func AesEncrypt(origData, key []byte) ([]byte, error) {
     block, err := aes.NewCipher(key)
     if err != nil {
          return nil, err
     }
     blockSize := block.BlockSize()
     origData = PKCS5Padding(origData, blockSize)
     blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
     crypted := make([]byte, len(origData))
	 
     blockMode.CryptBlocks(crypted, origData)
     return crypted, nil
}


func AesDecrypt(crypted, key []byte) ([]byte, error) {
     block, err := aes.NewCipher(key)
     if err != nil {
          return nil, err
     }
     blockSize := block.BlockSize()
     blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
     origData := make([]byte, len(crypted))
     blockMode.CryptBlocks(origData, crypted)
     origData = PKCS5UnPadding(origData)
     return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func String2Bytes(a string) (r []byte){
	r = make([]byte,8*len(a))
	for k,v := range []byte(a){
		r[k] = byte(v)
	}
	return 
}

func main(){
	
	G,P := DH_generate_G_P()
	fmt.Println("G")
	Print_16(G)
	fmt.Println("P")
	Print_16(P)
	
	
	a_pub_key,a_pri_key := DH_generate_key_pair(G,P)
	b_pub_key,b_pri_key := DH_generate_key_pair(G,P)
	fmt.Println("A PRI_KEY")
	Print_16(a_pri_key)
	fmt.Println("A PUB_KEY")
	Print_16(a_pub_key)
	fmt.Println("B PRI_KEY")
	Print_16(b_pri_key)
	fmt.Println("B PUB_KEY")
	Print_16(b_pub_key)
	
	a_secret_key := DH_generate_key_secret(G,P,a_pri_key,b_pub_key)
	b_secret_key := DH_generate_key_secret(G,P,b_pri_key,a_pub_key)
	fmt.Println("A secret_key")
	Print_16(a_secret_key)
	fmt.Println("B secret_key")
	Print_16(b_secret_key)
	plaintext := "this is a message!"
	plaintext1 := String2Bytes(plaintext)
	fmt.Println("ciphertext")
	ciphertext,_ := AesEncrypt(plaintext1,a_secret_key.Str_16)
	fmt.Println(string(ciphertext))
	fmt.Println("plaintext")
	plaintext2,_ := AesDecrypt(ciphertext,a_secret_key.Str_16)
	fmt.Println(string(plaintext2))
	
}