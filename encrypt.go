package small_rsa

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"github.com/Rian-wahid/seal"
)

func Encrypt(pbk *PublicKey,b []byte)([]byte,error){

	if pbk==nil || b==nil || len(b)==0{
		return nil,errors.New("cant encrypt")
	}
	if pbk.e==nil || pbk.n==nil {
		return nil,errors.New("cant encrypt")
	}
	if len(b)>38 {
		return nil,errors.New("message too long")
	}
	bb:=make([]byte,40)
	rand.Read(bb)
	if bb[0]==0 {
		bb[0]=1
	}
	paddingLen:=byte(38-len(b))
	bb[1]=paddingLen
	copy(bb[2+int(paddingLen):],b)
	msg:=big.NewInt(0).SetBytes(bb)
	encrypted:=big.NewInt(0)
	seal.VeryRandOP()
	subtle.WithDataIndependentTiming(func (){
		encrypted.Exp(msg,pbk.e,pbk.n)
	})
	seal.VeryRandOP()
	ciphertext:=encrypted.Bytes()
	cLen:=uint16(len(ciphertext))
	h:=sha256.New()
	h.Write(bb)
	cl:=make([]byte,2)
	binary.BigEndian.PutUint16(cl,cLen)
	cl=append(cl,ciphertext...)
	return append(cl,h.Sum(nil)...),nil
}

func Decrypt(pvk *PrivateKey,b []byte) ([]byte,error){
	if b==nil || pvk==nil {
		return nil,errors.New("cant decrypt")
	}
	if pvk.n==nil || pvk.d==nil {
		return nil,errors.New("cant decrypt")
	}
	if len(b)<=2 {
		return nil,errors.New("cant decrypt")
	}
	cLen:=binary.BigEndian.Uint16(b[:2])
	if len(b)<int(cLen)+34 {
		return nil,errors.New("cant decrypt")
	}
	enc:=big.NewInt(0).SetBytes(b[2:2+int(cLen)])
	dec:=big.NewInt(0)
	seal.VeryRandOP()
	subtle.WithDataIndependentTiming(func (){
		dec.Exp(enc,pvk.d,pvk.n)
	})
	seal.VeryRandOP()
	decBytes:=dec.Bytes()
	h:=sha256.New()
	h.Write(decBytes)
	auth:=h.Sum(nil)
	if subtle.ConstantTimeCompare(auth,b[2+int(cLen):2+int(cLen)+32])!=1 {
		return nil,errors.New("decryption failed")
	}
	paddingLen:=int(decBytes[1])
	msg:=decBytes[2+paddingLen:]
	return msg,nil
}

