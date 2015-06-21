package crypto

import (
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSignature(t *testing.T) {
	s := NewSignature(Random(128))

	k, v := "name", []byte("Hello Signature")
	Convey("[crypto#Signature]", t, func() {
		value, err := s.Encode(k, v)
		So(value, ShouldNotBeNil)
		So(err, ShouldBeNil)

		src, err := s.Decode(k, value)
		So(bytes.Compare(v, src), ShouldEqual, 0)
		So(err, ShouldBeNil)
	})
}
