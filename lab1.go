package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/fullsailor/pkcs7"
)

//func init() {
//
//	flag.StringVar(&Mode, "mode", "", "Here you should place z - to zip, sz - to sertificate zip, u - to unzip")
//	flag.StringVar(&Hash, "hash", "", "")
//	flag.StringVar(&CertName, "cert", "./my.crt", "")
//	flag.StringVar(&KeyName, "pkey", "./my.key", "")
//	flag.StringVar(&Path, "path", "./", "")
//	flag.StringVar(&Output, "out", "archive.szip", "")
//}

var crtLocation string = "./my.cer"
var keyLocation string = "./my.key"

func main() {
	var hash string
	flag.StringVar(&hash, "hash", "UNDEF", "hash")
	fmt.Println("--------------------")
	var mode string
	flag.StringVar(&mode, "mode", "z", "режим работы приложения")
	flag.Parse()
	switch mode {
	case "z":
		err := prepareSzip()
		if err != nil {
			fmt.Printf("Error occured: %s\nReason is here:\n%s", err, debug.Stack())
			return
		}
		fmt.Println("Your archive has been successfuly Szpped")

	case "i":
		err := info(hash)
		if err != nil {
			log.Fatal(err)
			return
		}

	default:
		fmt.Println("Uknown command. Please read manual and restart the application")
	}
}

//------------------------------------------------------------------------------------

func signData(data []byte) (sighed []byte, err error) {
	var signedData *pkcs7.SignedData
	if signedData, err = pkcs7.NewSignedData(data); err != nil {
		return
	}
	var cert tls.Certificate
	if cert, err = tls.LoadX509KeyPair("./my.cer", "./my.key"); err != nil {
		return
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("Не удалось загрузить сертификат")
	}
	rsaKey := cert.PrivateKey
	var rsaCert *x509.Certificate
	if rsaCert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return
	}
	if err = signedData.AddSigner(rsaCert, rsaKey, pkcs7.SignerInfoConfig{}); err != nil {
		return
	}
	return signedData.Finish()
}

//------------------------------------------------------------------------------------

func prepareSzip() (err error) {
	var xMl, metaZip, zipData []byte
	collector := NewFileCollector()
	if err = collector.walkFiles("./test"); err != nil {
		return
	}

	if xMl, err = collector.meta2xml(); err != nil {
		return
	}

	metaCollector := NewFileCollector()
	if err = metaCollector.packFile("meta.xml", bytes.NewReader(xMl)); err != nil {
		return
	}

	if metaZip, err = metaCollector.zipData(); err != nil {
		return
	}

	if zipData, err = collector.zipData(); err != nil {
		return
	}

	return makeSzip(metaZip, zipData)
}

//------------------------------------------------------------------------------------

func makeSzip(metaZip, dataZip []byte) (err error) {
	resultBuf := new(bytes.Buffer)

	metaSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(metaSize, uint32(len(metaZip)))
	if err = binary.Write(resultBuf, binary.LittleEndian, metaSize); err != nil {
		return
	}

	fmt.Println(len(metaZip))

	if _, err = resultBuf.Write(metaZip); err != nil {
		return
	}

	if _, err = resultBuf.Write(dataZip); err != nil {
		return
	}

	var signedData []byte
	if signedData, err = signData(resultBuf.Bytes()); err != nil {
		return
	}

	if err = ioutil.WriteFile("test.szp", signedData, 0644); err != nil {
		return
	}
	return
}

//------------------------------------------------------------------------------------

//Единица передачи метаданных файла
type FileMeta struct {
	Name           string `xml:"filename"`
	OriginalSize   uint64 `xml:"original_size"`
	CompressedSize uint64 `xml:"compressed_size"`
	ModTime        string `xml:"mod_time"`
	//Sha1Hash       [20]byte `xml:"sha1_hash"`
}

//------------------------------------------------------------------------------------

//Для сбора итогового файла
type FileCollector struct {
	ZipBuf   *bytes.Buffer
	Zip      *zip.Writer
	MetaData []*FileMeta
}

//------------------------------------------------------------------------------------

//Конструктор по умолчанию
func NewFileCollector() *FileCollector {
	buf := new(bytes.Buffer)

	return &FileCollector{
		ZipBuf:   buf,
		Zip:      zip.NewWriter(buf),
		MetaData: make([]*FileMeta, 0, 100),
	}
}

//------------------------------------------------------------------------------------

func (f *FileCollector) walkFiles(path string) (err error) {
	var files []os.FileInfo
	var fileReader *os.File

	if files, err = ioutil.ReadDir(path); err != nil {
		return
	}

	for i := range files {
		fullPath := filepath.Join(path, files[i].Name())

		if files[i].IsDir() {
			if err = f.walkFiles(fullPath); err != nil {
				return
			}
			continue
		}

		f.addMeta(fullPath)
		if fileReader, err = os.Open(fullPath); err != nil {
			return
		}

		if err = f.packFile(fullPath, fileReader); err != nil {
			return
		}
	}
	return
}

//------------------------------------------------------------------------------------

func (f *FileCollector) meta2xml() (js []byte, err error) {
	js, err = xml.Marshal(f.MetaData)
	return js, err
}

//------------------------------------------------------------------------------------

func (f *FileCollector) addMeta(fullPath string) {
	f.MetaData = append(f.MetaData, &FileMeta{
		Name: fullPath,
	})
	return
}

//------------------------------------------------------------------------------------

func (f *FileCollector) packFile(filename string, fileReader io.Reader) (err error) {
	var fileWriter io.Writer
	if fileWriter, err = f.Zip.Create(filename); err != nil {
		return
	}

	if _, err = io.Copy(fileWriter, fileReader); err != nil {
		return
	}
	return
}

//------------------------------------------------------------------------------------

func (f *FileCollector) zipData() (data []byte, err error) {
	if err = f.Zip.Close(); err != nil {
		return
	}

	data = f.ZipBuf.Bytes()
	return
}

//------------------------------------------------------------------------------------

func CheckSzp(szpLocation string, hash string) (error, *pkcs7.PKCS7) {
	szp, err := ioutil.ReadFile(szpLocation)
	if err != nil {
		return err, nil
	}

	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return err, nil
	}

	err = sign.Verify()
	if err != nil {
		return err, nil
	}

	signer := sign.GetOnlySigner()
	if signer == nil {
		return errors.New("Unable to obtain a single signer"), nil
	}

	if hash != "UNDEF" {
		if hash != fmt.Sprintf("%x", sha1.Sum(signer.Raw)) {
			fmt.Println(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
			return errors.New("ERROR: Certificate hash is corrupted"), nil
		}
	}

	crt, err := tls.LoadX509KeyPair(crtLocation, keyLocation)
	if err != nil {
		return err, nil
	}

	parsedCrt, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return err, nil
	}

	if bytes.Compare(parsedCrt.Raw, signer.Raw) != 0 {
		return errors.New("Certificates don't match"), nil
	}
	return nil, sign
}

//------------------------------------------------------------------------------------

func info(hash string) error {
	err, sign := CheckSzp("./test.szp", hash)
	if err != nil {
		return err
	}

	err, fileMetas := GetMeta(sign)
	if err != nil {
		//fmt.Println("ошибка 1")
		return err
	}

	fmt.Println(len(fileMetas))

	for _, file := range fileMetas {
		fmt.Println(file)
	}

	return err
}

//------------------------------------------------------------------------------------

func GetMeta(p *pkcs7.PKCS7) (error, []FileMeta) {
	//Read meta
	metaSize := int32(binary.LittleEndian.Uint32(p.Content[:4]))
	fmt.Println(metaSize)
	bytedMeta := bytes.NewReader(p.Content[4 : metaSize+4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		//fmt.Println("ошибка 2")
		return err, nil
	}

	metaCompressed := readableMeta.File[0] //meta.xml

	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		//fmt.Println("ошибка 3")
		return err, nil
	}
	defer metaUncompressed.Close()

	var fileMetas []FileMeta
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		//fmt.Println("ошибка 4")
		return err, nil
	}
	err = xml.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		//fmt.Println("ошибка 4")
		return err, nil
	}

	return err, fileMetas
}
