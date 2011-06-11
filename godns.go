package main

import (
	"bufio"
	"bytes"
	"dns"
	"fmt"
	"http"
	"io/ioutil"
	"json"
	"log"
	"net"
	"os"
	"strconv"
)

type Logger interface {
	Println(...interface{})
	Printf(string, ...interface{})
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
	logger.Println("Starting GoDNS")

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err == nil {
		logger.Println("Resolved listening address:", addr)
	} else {
		logger.Println("Failure resolving listening address:", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err == nil {
		logger.Println("Listening.")
	} else {
		logger.Fatalln(err)
	}

	for {
		listen(logger, conn)
	}
}

func listen(logger Logger, conn *net.UDPConn) {
	buffer := make([]byte, 1<<16) // according to tcpdump
	size, addr, _ := conn.ReadFromUDP(buffer)
	raw := buffer[0:size]

	msg := &dns.Msg{}
	msg.Unpack(raw)
	lookup := msg.Question[0].Name

	var lookupResult string
	logger.Println(lookup[len(lookup)-5:])
	if lookup[len(lookup)-5:] == ".bit." {
		lookupResult = bitcoindLookup(lookup)

		if lookupResult != "" {
			logger.Println(lookup, "=>", lookupResult)

			out, _ := createResponse(msg, lookup, lookupResult)
			conn.WriteToUDP(out, addr)
			return
		}
	}

	// fall back to other lookup

	msg.Rcode = dns.RcodeNameError
	msg.Response = true
	msg.Authoritative = false
	msg.Recursion_desired = true
	msg.Recursion_available = false
	out, _ := msg.Pack()
	conn.WriteToUDP(out, addr)
}

func createResponse(msg *dns.Msg, name, ipstr string) (out []byte, ok bool) {
	ip := net.ParseIP(ipstr).To4()
	if len(ip) != 4 {
		return
	}
	fmt.Printf("ip: %#v\n", ip)

	var a uint32
	rra := &dns.RR_A{}
	rra.A = (a | uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))

	rrh := &dns.RR_Header{
		Name:     name,
		Rrtype:   dns.TypeA,
		Class:    dns.ClassINET,
		Ttl:      60,
		Rdlength: 100,
	}
	rra.Hdr = *rrh

	fmt.Printf("%#v", rra.Hdr)
	fmt.Printf("%#v", rra)

	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append(msg.Answer, rra)
	msg.Response = true
	msg.Authoritative = true
	msg.Recursion_desired = true
	msg.Recursion_available = true

	out, ok = msg.Pack()
	return
}
