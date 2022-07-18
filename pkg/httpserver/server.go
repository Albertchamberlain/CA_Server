package httpserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"myca/pkg/ca"
	"net/http"
	"sync"
)

var server *http.Server
var running bool

func init() {
}

func Run() {
	if running {
		return
	}

	mux := http.NewServeMux() //http多路复用器
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/csr-template", getCsrTemplateHandler) //获取csr模板
	mux.HandleFunc("/csr", signCsrHandler)                 //签发csr

	server = &http.Server{
		Addr:    ":8001",
		Handler: mux,
	}
	running = true
	if err := server.ListenAndServe(); err != nil {
		running = false
		log.Fatal(err)
		log.Println("server stop")
	}
	running = false
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.Write([]byte("error"))
		return
	}
	w.Write(body)
}

func getCsrTemplateHandler(w http.ResponseWriter, r *http.Request) { //获取csr模板
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	csr := ca.CertificateSigningRequest{
		SubjectCountry:            []string{"China"},
		SubjectOrganization:       []string{"Qinghua"},
		SubjectOrganizationalUnit: []string{"ComputerScience"},
		SubjectProvince:           []string{"Beijing"},
		SubjectLocality:           []string{"北京"},

		SubjectCommonName: "tsinghua.edu.cn",
		EmailAddresses:    []string{"ex@example.com"},
		DNSNames:          []string{"localhost"},
	}

	csrBytes, err := json.Marshal(csr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "application/json")
	w.Write(csrBytes)
}

func signCsrHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	csr := &ca.CertificateSigningRequest{}
	err = json.Unmarshal(reqBody, csr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(1) //开一个goroutine
	go signCsrRoutine(w, csr, &wg)
	wg.Wait()
}

func signCsrRoutine(w http.ResponseWriter, csr *ca.CertificateSigningRequest, wg *sync.WaitGroup) {
	defer wg.Done()
	theCert, err := ca.CA.SignX509(csr)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error happen: %v", err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Header().Add("Content-Type", "application/json")
	jsonByte, _ := json.Marshal(theCert)
	w.Write(jsonByte)

}
