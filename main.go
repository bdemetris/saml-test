package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/pkg/errors"
)

var file = "resp.txt"

func sendProfile(w http.ResponseWriter, r *http.Request) {
	f, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(errors.Wrap(err, "failed to read "+file+""))
	}
	mime := http.DetectContentType(f)
	fileSize := len(string(f))

	// fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "cn"))

	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", "attachment; filename="+file+"")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Content-Length", strconv.Itoa(fileSize))
	w.Header().Set("Content-Control", "private, no-transform, no-store, must-revalidate")

	http.ServeContent(w, r, file, time.Now(), bytes.NewReader(f))
	w.Write([]byte(samlsp.AttributeFromContext(r.Context(), "cn")))
}

func loadSamlOptions() (*samlsp.Middleware, error) {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		return nil, errors.Wrap(err, "failed to load keypair")
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse keypair")
	}

	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse idp url")
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse root url")
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
	})

	return samlSP, nil
}

func main() {

	samlSP, err := loadSamlOptions()
	if err != nil {
		panic(err)
	}
	app := http.HandlerFunc(sendProfile)
	http.Handle("/", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)

	// SECURITY : Only expose the file permitted for download.
	http.Handle("/"+file, http.FileServer(http.Dir("./")))
	http.ListenAndServe(":8000", nil)
}
