package small_rsa

import (

	"math/big"
	"errors"
	"encoding/binary"
	"github.com/Rian-wahid/seal"
)



type PrivateKey struct {
	d *big.Int
	n *big.Int
}

type PublicKey struct {
	e *big.Int
	n *big.Int
}

func GenerateKey(p,q *big.Int)(*PrivateKey, *PublicKey, error){

	minMsg:=[]byte{2}
	
	maxMsg41byte:= make([]byte,41)
	for i:=0; i<len(maxMsg41byte); i++{
		maxMsg41byte[i]=255
	}

	if p.BitLen()<180 || q.BitLen()<180 {
		return nil,nil,errors.New("prime with size lower than 180 bit not allowed")
	}

	if !p.ProbablyPrime(1) || !q.ProbablyPrime(1) { 
		return nil,nil,errors.New("p or q not prime")
	}
	e:=big.NewInt(65537)
	n:=big.NewInt(0).Mul(p,q)
	seal.VeryRandOP()
	b1:=big.NewInt(1)
	phi_n:=big.NewInt(0).Mul(big.NewInt(0).Sub(p,b1),big.NewInt(0).Sub(q,b1))
	seal.VeryRandOP()
	for big.NewInt(0).GCD(nil,nil,e,phi_n).Cmp(b1)!=0 {
		e.Add(e,b1)
	}
	d:=big.NewInt(0).ModInverse(e,phi_n)
	seal.VeryRandOP()
	miMsg:=big.NewInt(0).SetBytes(minMsg)
	maMsg:=big.NewInt(0).SetBytes(maxMsg41byte)
	miEnc:=big.NewInt(0).Exp(miMsg,e,n)
	seal.VeryRandOP()
	miDec:=big.NewInt(0).Exp(miEnc,d,n)
	if miMsg.Cmp(miDec)!=0 {
		return nil,nil, errors.New("cant use p or q for generate key")
	}
	maEnc:=big.NewInt(0).Exp(maMsg,e,n)
	seal.VeryRandOP()
	maDec:=big.NewInt(0).Exp(maEnc,d,n)
	if maMsg.Cmp(maDec) != 0 {
		return nil,nil, errors.New("cant use p or q for generate key")
	}
	return &PrivateKey{d:d,n:n},&PublicKey{e:e,n:n},nil
}

func (pbk *PublicKey) Destroy() {
	pbk.e.SetBytes([]byte{0})
	pbk.n.SetBytes([]byte{0})
	pbk.e=nil
	pbk.n=nil
}

func (pvk *PrivateKey) Destroy() {
	pvk.d.SetBytes([]byte{0})
	pvk.n.SetBytes([]byte{0})
	pvk.d=nil
	pvk.n=nil
}

func (pbk* PublicKey) ToBytes()[]byte{
	if pbk.e==nil || pbk.n==nil {
		return nil
	}
	bytesE:=pbk.e.Bytes()
	bytesN:=pbk.n.Bytes()
	bytesLenE:=uint16(len(bytesE))
	bytesLenN:=uint16(len(bytesN))
	b:=make([]byte,4)
	binary.BigEndian.PutUint16(b[:2],bytesLenE)
	binary.BigEndian.PutUint16(b[2:4],bytesLenN)
	b=append(b,bytesE...)
	b=append(b,bytesN...)
	return b
	
}

func PublicKeyFromBytes(b []byte)(*PublicKey,error){

	if b==nil {
		return nil,errors.New("b is nil")
	}
	if len(b)<=4 {
		return nil,errors.New("cant create key from bytes")
	}
	bytesLenE:=binary.BigEndian.Uint16(b[:2])
	bytesLenN:=binary.BigEndian.Uint16(b[2:4])
	if len(b)<4+int(bytesLenE+bytesLenN) {
		return nil,errors.New("cant create key from bytes")
	}
	e:=big.NewInt(0).SetBytes(b[4:4+int(bytesLenE)])
	n:=big.NewInt(0).SetBytes(b[4+int(bytesLenE):4+int(bytesLenE+bytesLenN)])

	return &PublicKey{e:e,n:n},nil
}

func (pvk *PrivateKey) ToBytes()[]byte {
	if pvk.d==nil || pvk.n==nil {
		return nil
	}
	bytesD:=pvk.d.Bytes()
	bytesN:=pvk.n.Bytes()
	bytesLenD:=uint16(len(bytesD))
	bytesLenN:=uint16(len(bytesN))
	b:=make([]byte,4)
	binary.BigEndian.PutUint16(b[:2],bytesLenD)
	binary.BigEndian.PutUint16(b[2:4],bytesLenN)
	b=append(b,bytesD...)
	b=append(b,bytesN...)
	return b
}

func PrivateKeyFromBytes(b []byte)(*PrivateKey,error){
	if b==nil {
		return nil,errors.New("b is nil")
	}
	if len(b)<=4 {
		return nil,errors.New("cant create key from bytes")
	}
	bytesLenD:=binary.BigEndian.Uint16(b[:2])
	bytesLenN:=binary.BigEndian.Uint16(b[2:4])
	if len(b)<4+int(bytesLenD+bytesLenN) {
		return nil,errors.New("cant create key from bytes")
	}
	d:=big.NewInt(0).SetBytes(b[4:4+int(bytesLenD)])
	n:=big.NewInt(0).SetBytes(b[4+int(bytesLenD):4+int(bytesLenD+bytesLenN)])

	return &PrivateKey{d:d,n:n},nil
}


