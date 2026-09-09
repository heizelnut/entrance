package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(h, "wrong") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("garbage", "x") {
		t.Fatal("garbage hash accepted")
	}
}

func TestToken(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 || a == b {
		t.Fatalf("token %q %q", a, b)
	}
	h := HashToken(a)
	if h == a || len(h) != 64 {
		t.Fatalf("hash %q", h)
	}
	if HashToken(a) != HashToken(a) {
		t.Fatal("hash not stable")
	}
}
