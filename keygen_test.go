package small_rsa

import (
	"testing"
	"crypto/rand"
	"fmt"
	"time"
	"github.com/stretchr/testify/assert"
)

func TestCreateKey(t *testing.T) {
	p,_:=rand.Prime(rand.Reader,193)
	q,_:=rand.Prime(rand.Reader,189)
	st:=time.Now()
	pvk,pbk,err:=GenerateKey(p,q)
	tt:=time.Now()
	fmt.Println(tt.Sub(st))
	assert.Nil(t,err)
	pvkb:=pvk.ToBytes()
	pbkb:=pbk.ToBytes()
	assert.NotNil(t,pvkb)
	assert.NotNil(t,pbkb)
	pvkfb,err:=PrivateKeyFromBytes(pvkb)
	assert.Nil(t,err)
	assert.NotNil(t,pvkfb)
	assert.Equal(t,pvk.n.String(),pvkfb.n.String())
	assert.Equal(t,pvk.d.String(),pvkfb.d.String())
	
	pbkfb,err:=PublicKeyFromBytes(pbkb)
	assert.Nil(t,err)
	assert.NotNil(t,pbkfb)
	assert.Equal(t,pbk.n.String(),pbkfb.n.String())
	assert.Equal(t,pbk.e.String(),pbkfb.e.String())
	
	pvk.Destroy()
	pbk.Destroy()
	pvkfb.Destroy()
	pbkfb.Destroy()
	assert.Nil(t,pvk.n)
	assert.Nil(t,pvk.d)
	assert.Nil(t,pbk.e)
	assert.Nil(t,pbk.n)
	assert.Nil(t,pvkfb.n)
	assert.Nil(t,pvkfb.d)
	assert.Nil(t,pbkfb.e)
	assert.Nil(t,pbkfb.n)

}
