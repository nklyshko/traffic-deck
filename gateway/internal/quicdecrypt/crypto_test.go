package quicdecrypt

import (
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// RFC 9001 Appendix A.1: Initial secrets + keys derived from the client DCID.
func TestInitialKeysRFC9001(t *testing.T) {
	dcid := unhex(t, "8394c8f03e515708")
	client, server := initialSecrets(dcid)
	if got := hex.EncodeToString(client); got != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Errorf("client_initial_secret = %s", got)
	}
	if got := hex.EncodeToString(server); got != "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" {
		t.Errorf("server_initial_secret = %s", got)
	}
	check := func(name, secretHex, label string, n int, want string) {
		got := hex.EncodeToString(hkdfExpandLabel(aes128gcm.newHash, unhex(t, secretHex), label, n))
		if got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	cs := hex.EncodeToString(client)
	check("client key", cs, "quic key", 16, "1f369613dd76d5467730efcbe3b1a22d")
	check("client iv", cs, "quic iv", 12, "fa044b2f42a3fd3b46fb255c")
	check("client hp", cs, "quic hp", 16, "9f50449e04a0e810283a1e9933adedd2")
	ss := hex.EncodeToString(server)
	check("server key", ss, "quic key", 16, "cf3a5331653c364c88f0f379b6067e37")
	check("server iv", ss, "quic iv", 12, "0ac1493ca1905853b0bba03e")
	check("server hp", ss, "quic hp", 16, "c206b8d9b9f0f37644430b490eeaa314")
}

// RFC 9001 Appendix A.2: decrypt the client Initial packet (AES-128-GCM + AES header
// protection) and confirm the payload starts with the expected CRYPTO frame.
func TestDecryptClientInitialRFC9001(t *testing.T) {
	packet := unhex(t, "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")
	wantPrefix := unhex(t, "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
	dcid := unhex(t, "8394c8f03e515708")
	client, _ := initialSecrets(dcid)
	k, err := deriveKeys(client, aes128gcm)
	if err != nil {
		t.Fatal(err)
	}
	// header: c3 ver(4) dcidlen(1)=08 dcid(8) scidlen(1)=00 tokenlen(1)=00 length(2)=449e
	// → pnOffset = 1+4+1+8+1+0+1+2 = 18; length 0x449e = 1182 → payloadEnd = 18+1182.
	hdr, pt, pn, ok := k.open(packet, 18, 18+1182, true, 0)
	if !ok {
		t.Fatal("decrypt failed")
	}
	if pn != 2 {
		t.Errorf("packet number = %d, want 2", pn)
	}
	if hdr[0] != 0xc3 {
		t.Errorf("unprotected first byte = %#x, want 0xc3", hdr[0])
	}
	if !strings.HasPrefix(hex.EncodeToString(pt), hex.EncodeToString(wantPrefix)) {
		t.Errorf("payload prefix mismatch; got %s…", hex.EncodeToString(pt)[:80])
	}
}

// RFC 9001 Appendix A.5: decrypt a ChaCha20-Poly1305 short-header packet (PING frame).
func TestDecryptChaChaShortHeaderRFC9001(t *testing.T) {
	secret := unhex(t, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	s, _ := suiteByID(0x1303)
	k, err := deriveKeys(secret, s)
	if err != nil {
		t.Fatal(err)
	}
	packet := unhex(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	// short header: 1 flags byte + 0-length DCID → pnOffset = 1; full packet is 21 bytes.
	_, pt, pn, ok := k.open(packet, 1, len(packet), false, 654360563)
	if !ok {
		t.Fatal("decrypt failed")
	}
	if pn != 654360564 {
		t.Errorf("packet number = %d, want 654360564", pn)
	}
	if hex.EncodeToString(pt) != "01" {
		t.Errorf("plaintext = %s, want 01", hex.EncodeToString(pt))
	}
}
