package main

import (
	"log"
	"json"
	"os"
	"net"
	"strconv"
	"io/ioutil"
	"bytes"
	"fmt"
	"bufio"
	"http"
	"dns"
)

type Logger interface {
	Println(...interface{})
	Fatalln(...interface{})
}

type RPCData struct {
	Jsonrpc string        "jsonrpc"
	Id      string        "id"
	Method  string        "method"
	Params  []interface{} "params"
}

type RPCError struct {
	Code    int    "code"
	Message string "message"
}

type ResultDetail struct {
	Value     string "value"
	Name      string "name"
	ExpiresIn int    "expires_in"
	TxId      string "txid"
}

type RPCNameScanResponse struct {
	Result []ResultDetail "result"
	Error  RPCError
	Id     string "id"
}

func namecoindPOST(body *bytes.Buffer) (response *http.Response, err os.Error) {
	client := http.Client{}

	var req http.Request
	req.Method = "POST"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Close = true
	req.Body = ioutil.NopCloser(body)
	req.Header = http.Header{
		"Content-Type":   []string{"text/plain"},
		"Content-Length": []string{strconv.Itoa(body.Len())},
	}
	req.ContentLength = int64(body.Len())
	req.URL, err = http.ParseURL("http://manveru:pass@127.0.0.1:8332/")
	if err != nil {
		fmt.Println("err:", err)
	}

	return client.Do(&req)
}

func namecoidRequest(data RPCData) (responseBody []byte) {
	jsonData, err := json.Marshal(data)
	response, err := namecoindPOST(bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("err:", err)
	}

	if response.StatusCode == 200 {
		reader := bufio.NewReader(response.Body)
		responseBody = make([]byte, response.ContentLength)
		_, err := reader.Read(responseBody)
		if err != nil {
			panic(err)
		}
	}

	return
}

type RPCNameScanValue struct {
	Map map[string]string "map"
}

func bitcoindLookup(name string) (addr string) {
	params := make([]interface{}, 2)
	params[0] = "d/" + name[0:len(name)-5]
	params[1] = 1
	data := RPCData{Jsonrpc: "1.0", Id: "godns", Method: "name_scan", Params: params}
	fmt.Println(data)
	responseBody := namecoidRequest(data)

	var response RPCNameScanResponse
	json.Unmarshal(responseBody, &response)
	fmt.Printf("%#v\n", response)

	var value RPCNameScanValue
	results := response.Result
	if len(results) == 0 {
		return
	}
	resultValue := results[0].Value
	json.Unmarshal([]uint8(resultValue), &value)
	fmt.Printf("%#v\n", value)

	if value.Map != nil {
		addr = value.Map[""]
	}

	return
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Println("The GoDNS")

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	logger.Println("addr:", addr, "err:", err)

	conn, err := net.ListenUDP("udp", addr)
	logger.Println("conn:", conn, "err:", err)

	for {
		listen(logger, conn)
	}
}

func listen(logger Logger, conn *net.UDPConn) {
	buffer := make([]byte, 1<<16) // according to tcpdump
	size, addr, err := conn.ReadFromUDP(buffer)
	logger.Println("size:", size, "addr:", addr, "err:", err)
	raw := buffer[0:size]

	msg := &dns.Msg{}
	msg.Unpack(raw)
	logger.Println("msg:", msg)
	lookup := msg.Question[0].Name
	lookupResult := bitcoindLookup(lookup)
	fmt.Printf("lookupResult: %#v\n", lookupResult)

	rra := &dns.RR_A{}
	ip := net.ParseIP(lookupResult).To4()
	if len(ip) != 4 {
		return
	}
	fmt.Printf("ip: %#v\n", ip)

	var a uint32
	rra.A = (a | uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))

	rrh := &dns.RR_Header{
		Name:     lookup,
		Rrtype:   dns.TypeA,
		Class:    dns.ClassINET,
		Ttl:      60,
		Rdlength: 100,
	}
	rra.Hdr = *rrh

  fmt.Printf("%#v", rra.Hdr)
  fmt.Printf("%#v", rra)

	msg.Answer = append(msg.Answer, rra)
	msg.Response = true
	msg.Authoritative = true
	msg.Recursion_desired = true
	msg.Recursion_available = true

	out, _ := msg.Pack()
	conn.WriteToUDP(out, addr)
}
