package small_rsa

import (
	"testing"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	p,_:=rand.Prime(rand.Reader,193)
	q,_:=rand.Prime(rand.Reader,189)
	pvk,pbk,err:=GenerateKey(p,q)
	assert.Nil(t,err)
	assert.NotNil(t,pvk)
	assert.NotNil(t,pbk)
	
	msg:=[]byte("a secret message")

	ciphertext,err:=Encrypt(pbk,msg)
	assert.Nil(t,err)
	assert.NotEqual(t,string(msg),string(ciphertext))
	assert.NotEqual(t,len(msg),len(ciphertext))

	decrypted,err:=Decrypt(pvk,ciphertext)
	assert.Nil(t,err)
	assert.Equal(t,string(msg),string(decrypted))

}
