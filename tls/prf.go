/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"hash"

	"github.com/OblivionTime/gmhttp/gmsm/sm3"
)

/*
var (
	piligoBuffer = make([]byte, 0)
)
*/
/*
// Split a premaster secret in two as specified in RFC 4346, section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return
}
*/
// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
func gmprf11(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)
		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

const (
	tlsRandomLength      = 32 // Length of a random nonce in TLS 1.1.
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

func prfAndHashForVersion(version uint16, suite *cipherSuite) (func(result, secret, label, seed []byte), crypto.Hash) {
	switch version {
	case VersionGMTLS: //国密计算
		return gmprf11(sm3.New), crypto.Hash(0)
	default:
		panic("unknown version")
	}
}

func prfForVersion(version uint16, suite *cipherSuite) func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion(version, suite)
	return prf
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See http://tools.ietf.org/html/rfc5246#section-8.1
func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte) []byte {

	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, masterSecretLength)
	//国密masterkey 计算方式PRF(pre_master_secret,"mastersecret",c.random+s.random)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed)

	//fmt.Println(hex.Dump(masterSecret))
	return masterSecret
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	n := 2*macLen + 2*keyLen + 2*ivLen

	keyMaterial := make([]byte, n)
	prfForVersion(version, suite)(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]

	return
}

// lookupTLSHash looks up the corresponding crypto.Hash for a given
// TLS hash identifier.
func lookupTLSHash(hash uint8) (crypto.Hash, error) {
	switch hash {
	case hashSHA1:
		return crypto.SHA1, nil
	case hashSHA256:
		return crypto.SHA256, nil
	case hashSHA384:
		return crypto.SHA384, nil
	default:
		return 0, errors.New("tls: unsupported hash algorithm")
	}
}

func newFinishedHash(version uint16, cipherSuite *cipherSuite) finishedHash {

	var buffer []byte
	if version == VersionSSL30 || version >= VersionTLS12 {
		buffer = []byte{}
	}

	prf, hash := prfAndHashForVersion(version, cipherSuite)
	if hash != 0 {
		return finishedHash{hash.New(), hash.New(), nil, nil, buffer, version, prf}
	}
	//限定国密使用
	if version != VersionGMTLS {
		panic("version not gmtls")
	} else {
		return finishedHash{sm3.New(), sm3.New(), nil, nil, buffer, version, prf}
	}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)
	if h.version < VersionTLS12 && h.version != VersionGMTLS {
		h.clientMD5.Write(msg)
		h.serverMD5.Write(msg)
	}
	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	if h.version >= VersionTLS12 || h.version == VersionGMTLS {
		return h.client.Sum(nil)
	}
	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

func (h finishedHash) SumSvr() []byte {
	if h.version >= VersionTLS12 || h.version == VersionGMTLS {
		return h.server.Sum(nil)
	}
	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

// finishedSum30 calculates the contents of the verify_data member of a SSLv3
// Finished message given the MD5 and SHA1 hashes of a set of handshake
// messages.
func finishedSum30(md5, sha1 hash.Hash, masterSecret []byte, magic []byte) []byte {
	md5.Write(magic)
	md5.Write(masterSecret)
	md5.Write(ssl30Pad1[:])
	md5Digest := md5.Sum(nil)

	md5.Reset()
	md5.Write(masterSecret)
	md5.Write(ssl30Pad2[:])
	md5.Write(md5Digest)
	md5Digest = md5.Sum(nil)

	sha1.Write(magic)
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad1[:40])
	sha1Digest := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad2[:40])
	sha1.Write(sha1Digest)
	sha1Digest = sha1.Sum(nil)

	ret := make([]byte, len(md5Digest)+len(sha1Digest))
	copy(ret, md5Digest)
	copy(ret[len(md5Digest):], sha1Digest)
	return ret
}

var ssl3ClientFinishedMagic = [4]byte{0x43, 0x4c, 0x4e, 0x54}
var ssl3ServerFinishedMagic = [4]byte{0x53, 0x52, 0x56, 0x52}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	//)
	if h.version == VersionSSL30 {
		return finishedSum30(h.clientMD5, h.client, masterSecret, ssl3ClientFinishedMagic[:])
	}
	csum := h.Sum()

	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, clientFinishedLabel, csum)

	return out
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {

	if h.version == VersionSSL30 {
		return finishedSum30(h.serverMD5, h.server, masterSecret, ssl3ServerFinishedMagic[:])
	}
	out := make([]byte, finishedVerifyLength)
	outsm3 := h.SumSvr()

	h.prf(out, masterSecret, serverFinishedLabel, outsm3)

	return out
}

// selectClientCertSignatureAlgorithm returns a signatureAndHash to sign a
// client's CertificateVerify with, or an error if none can be found.
func (h finishedHash) selectClientCertSignatureAlgorithm(serverList []signatureAndHash, sigType uint8) (signatureAndHash, error) {
	if h.version < VersionTLS12 {
		// Nothing to negotiate before TLS 1.2.
		return signatureAndHash{signature: sigType}, nil
	}

	for _, v := range serverList {
		if v.signature == sigType && isSupportedSignatureAndHash(v, supportedSignatureAlgorithms) {
			return v, nil
		}
	}
	return signatureAndHash{}, errors.New("tls: no supported signature algorithm found for signing client certificate")
}

// hashForClientCertificate returns a digest, hash function, and TLS 1.2 hash
// id suitable for signing by a TLS client certificate.
func (h finishedHash) hashForClientCertificate(signatureAndHash signatureAndHash, masterSecret []byte) ([]byte, crypto.Hash, error) {
	if (h.version == VersionSSL30 || h.version >= VersionTLS12) && h.buffer == nil {
		panic("a handshake hash for a client-certificate was requested after discarding the handshake buffer")
	}

	if h.version == VersionSSL30 {
		if signatureAndHash.signature != signatureRSA {
			return nil, 0, errors.New("tls: unsupported signature type for client certificate")
		}

		md5Hash := md5.New()
		md5Hash.Write(h.buffer)
		sha1Hash := sha1.New()
		sha1Hash.Write(h.buffer)
		return finishedSum30(md5Hash, sha1Hash, masterSecret, nil), crypto.MD5SHA1, nil
	}
	if h.version >= VersionTLS12 {
		hashAlg, err := lookupTLSHash(signatureAndHash.hash)
		if err != nil {
			return nil, 0, err
		}
		hash := hashAlg.New()
		hash.Write(h.buffer)
		return hash.Sum(nil), hashAlg, nil
	}

	if signatureAndHash.signature == signatureECDSA {
		return h.server.Sum(nil), crypto.SHA1, nil
	}

	return h.Sum(), crypto.MD5SHA1, nil
}

// discardHandshakeBuffer is called when there is no more need to
// buffer the entirety of the handshake messages.
func (h *finishedHash) discardHandshakeBuffer() {
	h.buffer = nil
}
