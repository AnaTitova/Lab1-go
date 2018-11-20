package main

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/fullsailor/pkcs7"
)

func main() {
	fmt.Println("test")
	var mode string
	flag.StringVar(&mode, "mode", "z", "режим работы приложения")
	flag.Parse()
	var err error
	switch mode {
	case "z":
		{
			err = prepareSzip()
			break
		}
		if err != nil {
			fmt.Printf("Ошибка: %s\nПричина:\n%s", err, debug.Stack())
		}
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
	var xml, metaZip, zipData []byte
	collector := NewFileCollector()
	if err = collector.walkFiles("./test"); err != nil {
		return
	}

	if xml, err = collector.meta2xml(); err != nil {
		return
	}

	metaCollector := NewFileCollector()
	if err = metaCollector.packFile("meta.xml", bytes.NewReader(xml)); err != nil {
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

	if err = binary.Write(resultBuf, binary.LittleEndian, uint32(len(metaZip))); err != nil {
		return
	}

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
	Name string `xml:"filename"`
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

func (f *FileCollector) meta2xml() (XML []byte, err error) {
	XML, err = xml.Marshal(f.MetaData)
	return XML, err
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
