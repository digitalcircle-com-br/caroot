package caroot

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"sync"
	"time"
)

var rootDir string = "certs"
var ca *x509.Certificate
var catls tls.Certificate
var start int64 = 0
var mtx sync.Mutex

func exists(s string) bool {
	_, err := os.Stat(s)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, nil
	}
}

func InitCA(rdir string, installca func(ca string)) error {
	if rdir != "" {
		rootDir = rdir
	}
	os.MkdirAll(rootDir, os.ModePerm)
	log.Printf("USING ROOT CA as: %s", rootDir)
	start = time.Now().Unix()
	if !exists(path.Join(rootDir, "ca.cer")) {
		log.Printf("Initiating new CA CERT")
		ca = &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().Unix()),
			Subject: pkix.Name{
				Organization:  []string{"Digital Circle"},
				Country:       []string{"BR"},
				Province:      []string{""},
				Locality:      []string{""},
				StreetAddress: []string{""},
				PostalCode:    []string{""},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1000, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		priv, _ := rsa.GenerateKey(rand.Reader, 4096)
		pub := &priv.PublicKey
		ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
		if err != nil {
			return err
		}
		out := &bytes.Buffer{}
		pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
		cert := out.Bytes()
		err = ioutil.WriteFile(path.Join(rootDir, "ca.cer"), cert, 0600)
		if err != nil {
			return err
		}
		keyOut, err := os.OpenFile(path.Join(rootDir, "ca.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		keyOut.Close()
		log.Print("written key.pem\n")
		if installca != nil {
			log.Printf("Installing CA")
			installca(path.Join(rootDir, "ca.cer"))
		}
	}
	var err error
	// Load CA
	catls, err = tls.LoadX509KeyPair(path.Join(rootDir, "ca.cer"), path.Join(rootDir, "ca.key"))
	if err != nil {
		return err
	}
	ca, err = x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		return err
	}

	return nil

}

func SetRootDir(d string) {
	rootDir = d
}
func GenCertForDomain(d string) (keybs []byte, certbs []byte, err error) {

	mtx.Lock()

	time.Sleep(time.Nanosecond)
	ser := time.Now().UnixNano()
	mtx.Unlock()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(ser),
		Subject: pkix.Name{
			Organization: []string{"Digital Circle"},
			Country:      []string{"BR"},
			CommonName:   d,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		//SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		//Extensions: []pkix.Extension{
		//	{
		//		Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
		//		Critical: false,
		//		Value:    rawByte,
		//	},
		//},
	}

	cert.DNSNames = append(cert.DNSNames, d)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	pub := &priv.PublicKey

	// Sign the certificate
	cert_b, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)
	if err != nil {
		return
	}
	// Public key
	certBuffer := &bytes.Buffer{}
	pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert_b})

	keyBuffer := &bytes.Buffer{}
	pem.Encode(keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	keybs = keyBuffer.Bytes()
	certbs = certBuffer.Bytes()
	return
}
func GenCertFilesForDomain(d string, dir string) error {
	key, cert, err := GenCertForDomain(d)
	if err != nil {
		return err
	}
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}
	keyfile := path.Join(dir, d+".key")
	certfile := path.Join(dir, d+".cer")
	err = ioutil.WriteFile(keyfile, key, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certfile, cert, 0600)
	if err != nil {
		return err
	}
	return nil
}
func GenCertFilesForDomainInRootDir(d string) {
	GenCertFilesForDomain(d, rootDir)
}
func GetCertFromRoot(d string) *tls.Certificate {
	cer, err := tls.LoadX509KeyPair(path.Join(rootDir, d+".cer"), path.Join(rootDir, d+".key"))
	if err != nil {
		return nil
	}
	return &cer
}
func GetOrGenFromRoot(d string) *tls.Certificate {
	if exists(path.Join(rootDir, d+".cer")) {
		return GetCertFromRoot(d)
	} else {
		GenCertFilesForDomainInRootDir(d)
		return GetCertFromRoot(d)
	}
}
func GetCATLS() tls.Certificate {
	return catls
}

//Muda Senha de bloco PEM
func ChangePEMBlockPassword(bspem []byte, oldpass []byte, newpass []byte) (ret []byte, err error) {
	oldblk, _ := pem.Decode(bspem)
	bs, err := x509.DecryptPEMBlock(oldblk, oldpass)
	if err != nil {
		return
	}
	encpem, err := x509.EncryptPEMBlock(
		rand.Reader,
		oldblk.Type,
		bs,
		newpass,
		x509.PEMCipherAES256)

	ret = pem.EncodeToMemory(encpem)
	return
}

//Gera par publico e privado em formato x509 - PKCS1
func GenPubPrivPair() (pub []byte, priv []byte, err error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	priv = x509.MarshalPKCS1PrivateKey(pk)
	pub = x509.MarshalPKCS1PublicKey(&pk.PublicKey)
	return
}

func PemEncodePubKey(bs []byte) []byte {
	blk := &pem.Block{
		Type:    "RSA Public Key",
		Headers: nil,
		Bytes:   bs,
	}
	return pem.EncodeToMemory(blk)
}

func PemEncodePrivKey(bs []byte) []byte {
	blk := &pem.Block{
		Type:    "RSA Private Key",
		Headers: nil,
		Bytes:   bs,
	}
	return pem.EncodeToMemory(blk)
}
