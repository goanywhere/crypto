package crypto

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func BenchmarkRandom(b *testing.B) {
	for index := 0; index < b.N; index++ {
		Random(32)
	}
}

func TestEncrypt(t *testing.T) {
	src := "I'mAPlainSecret"
	os.Setenv("SECRET_KEY", "secretkey@example.com")
	Convey("auth.Encrypt Test", t, func() {
		secret := Encrypt(src)
		So(len(secret), ShouldEqual, 60)
		So(secret, ShouldNotEqual, Encrypt(src))
		So(secret, ShouldNotEqual, Encrypt(src))
		So(secret, ShouldNotEqual, Encrypt(src))
		So(secret, ShouldNotEqual, Encrypt(src))
		So(secret, ShouldNotEqual, Encrypt(src))
	})
}

func TestVerify(t *testing.T) {
	src := "I'mAPlainSecret"
	//key := "secretkey@example.com"
	Convey("auth.Verify Test", t, func() {
		for index := 0; index < 10; index++ {
			secret := Encrypt(src)
			So(Verify(src, secret), ShouldBeTrue)
		}
	})
}

func BenchmarkMixin(b *testing.B) {
	src := "I'mAPlainSecret"
	os.Setenv("SECRET_KEY", "secretkey@example.com")
	for index := 0; index < b.N; index++ {
		mixin(src)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	src := "I'mAPlainSecret"
	os.Setenv("SECRET_KEY", "secretkey@example.com")
	for index := 0; index < b.N; index++ {
		Encrypt(src)
	}
}

func BenchmarkVerify(b *testing.B) {
	src := "I'mAPlainSecret"
	os.Setenv("SECRET_KEY", "secretkey@example.com")
	secret := Encrypt(src)
	for index := 0; index < b.N; index++ {
		Verify(src, secret)
	}
}
