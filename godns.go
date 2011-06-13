package main

import (
	"bufio"
	"bytes"
	"dns"
	"flag"
	"http"
	"io/ioutil"
	"json"
	"log"
	"net"
	"os"
	"fmt"
	"strconv"
	"strings"
)

type Options struct {
	nmcURL    *http.URL
	udpListen *net.UDPAddr
	dnsProxy  *net.UDPAddr
}

var (
	LOG           = log.New(os.Stdout, "", log.LstdFlags)
	options       = Options{}
	flagNmcUrl    *string = flag.String("nmc", "http://user:pass@127.0.0.1:8332/", "URI to connect to namecoind")
	flagUdpListen *string = flag.String("listen", "127.0.0.1:53", "UDP host:port to listen at")
	flagDnsProxy  *string = flag.String("dns", "8.8.8.8:53", "DNSd that handles non-.bit queries")
)

func usage(err os.Error) {
	fmt.Fprintf(os.Stderr, "usage: godns [options]\n")
	flag.PrintDefaults()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start:\n%s\n", err)
	}
	os.Exit(2)
}

func flagParse() {
	var err os.Error

	flag.Parse()

	(&options).nmcURL, err = http.ParseRequestURL(*flagNmcUrl)
	if err != nil {
		usage(err)
	}

	LOG.Println("Namecoind @", options.nmcURL)

	(&options).udpListen, err = net.ResolveUDPAddr("udp", *flagUdpListen)
	if err != nil {
		usage(err)
	}

	LOG.Println("Serving DNS @", options.udpListen)

	(&options).dnsProxy, err = net.ResolveUDPAddr("udp", *flagDnsProxy)
	if err != nil {
		usage(err)
	}

	LOG.Println("Proxy DNS @", options.dnsProxy)
}

func main() {
	LOG.Println("Starting GoDNS")

	flagParse()

	conn, err := net.ListenUDP("udp", options.udpListen)
	if err != nil {
		LOG.Fatalln(err)
	}

	for {
		listen(conn)
	}
}

func listen(conn *net.UDPConn) {
	buffer := make([]byte, 1<<16) // according to tcpdump
	size, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		LOG.Fatalln("Error trying to read:", err)
	}
	raw := buffer[0:size]

	msg := &dns.Msg{}
	msg.Unpack(raw)

	go respondTo(conn, addr, msg, raw)
}

func respondTo(conn *net.UDPConn, addr *net.UDPAddr, msg *dns.Msg, raw []uint8) {
	for _, question := range msg.Question {
		if strings.HasSuffix(question.Name, ".bit.") {
			respondWithDotBit(msg, question)
		} else {
			respondWithFallback(raw, msg, question)
		}
	}

	out, ok := msg.Pack()
	if ok == true {
		conn.WriteToUDP(out, addr)
	} else {
		LOG.Fatalln("msg.Pack() failed")
	}
}

// For now, we only answer queries for A and NS
func respondWithDotBit(msg *dns.Msg, question dns.Question) {
	// "foo.bar.bit." => ["foo", "bar", "bit"]
	name := strings.Split(question.Name[0:len(question.Name)-1], ".", -1)

	// edge case, if we get "bit." as question.Name
	// TODO: handle as proper error
	if len(name) <= 1 {
		return
	}
	// ["foo", "bar", "bit"] => ["foo", "bar"]
	name = name[0 : len(name)-1]

	LOG.Println("name:", name)

	// look up the root "d/bar"
	record, err := nmcLookup(name[len(name)-1])

	if err != nil {
		LOG.Fatalln(err)
	}

	LOG.Println(record)

	var value NMCValue
	json.Unmarshal([]uint8(record.Value), &value)

	LOG.Println(value)

	msg.Response = true

	switch question.Qtype {
	case dns.TypeA:
		answerA(msg, question, name, value)
	case dns.TypeAAAA:
		answerAAAA(msg, question, name, value)
		//case dns.TypeNS:    answerNS(msg)
		//case dns.TypeMD:    answerMD(msg)
		//case dns.TypeMF:    answerMF(msg)
		//case dns.TypeCNAME: answerCNAME(msg)
		//case dns.TypeSOA:   answerSOA(msg)
		//case dns.TypeMB:    answerMB(msg)
		//case dns.TypeMG:    answerMG(msg)
		//case dns.TypeMR:    answerMR(msg)
		//case dns.TypeNULL:  answerNULL(msg)
		//case dns.TypeWKS:   answerWKS(msg)
		//case dns.TypePTR:   answerPTR(msg)
		//case dns.TypeHINFO: answerHINFO(msg)
		//case dns.TypeMINFO: answerMINFO(msg)
		//case dns.TypeMX:    answerMX(msg)
		//case dns.TypeTXT:   answerTXT(msg)
		//case dns.TypeSRV:   answerSRV(msg)
	default:
		msg.Rcode = dns.RcodeNotImplemented
	}
}

func answerA(msg *dns.Msg, question dns.Question, name []string, value NMCValue) {
	var parsedIp net.IP
	// len == 1 means root domain: check "ip" and "map".""
	if len(name) == 1 {
		vips := value.Ip

		// this is legacy support
		if len(vips) == 0 {
			vmip := value.Map[""]
			if vmip == "" {
				// can't answer, make an error here.
				return
			} else {
				parsedIp = net.ParseIP(vmip)
			}
		} else {
			parsedIp = net.ParseIP(vips[0])
		}
	}

	ip := parsedIp.To4()
	if ip == nil {
		return
	}

	var a uint32
	rra := &dns.RR_A{}
	rra.A = (a | uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))

	rrh := &dns.RR_Header{
		Name:     question.Name,
		Rrtype:   dns.TypeA,
		Class:    dns.ClassINET,
		Ttl:      60,
		Rdlength: 100,
	}
	rra.Hdr = *rrh

	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append(msg.Answer, rra)
	msg.Response = true
	msg.Authoritative = true
	msg.Recursion_desired = true
	msg.Recursion_available = true
}

func answerAAAA(msg *dns.Msg, question dns.Question, name []string, value NMCValue) {
	var parsedIp net.IP
	// len == 1 means root domain: check "ip" and "map".""
	if len(name) == 1 {
		vips := value.Ip6

		if len(vips) == 0 {
			// can't answer, make an error here.
			return
		} else {
			parsedIp = net.ParseIP(vips[0])
		}
	}

	ip := parsedIp.To16()
	if ip == nil {
		return
	}

	rraaaa := &dns.RR_AAAA{}
	copy(ip, rraaaa.AAAA[:])

	rrh := &dns.RR_Header{
		Name:     question.Name,
		Rrtype:   dns.TypeAAAA,
		Class:    dns.ClassINET,
		Ttl:      60,
		Rdlength: 100,
	}
	rraaaa.Hdr = *rrh

	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append(msg.Answer, rraaaa)
	msg.Response = true
	msg.Authoritative = true
	msg.Recursion_desired = true
	msg.Recursion_available = true
}

func respondWithFallback(raw []uint8, clientMsg *dns.Msg, clientQuestion dns.Question) {
	conn, err := net.DialUDP("udp", nil, options.dnsProxy)
	if err != nil {
		LOG.Fatalln(err)
	}

	conn.WriteToUDP(raw, options.dnsProxy)

	buffer := make([]byte, 1<<16)
	size, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		LOG.Fatalln(err)
	}

	msg := &dns.Msg{}
	msg.Unpack(buffer[0:size])
	LOG.Println(msg)

	for _, answer := range msg.Answer {
		clientMsg.Answer = append(clientMsg.Answer, answer)
	}

	clientMsg.Rcode = msg.Rcode
	clientMsg.Response = msg.Response
	clientMsg.Authoritative = msg.Authoritative
	clientMsg.Recursion_desired = msg.Recursion_desired
	clientMsg.Recursion_available = msg.Recursion_available
}

type Mapping map[string]string

type NMCData struct {
	Jsonrpc string        "jsonrpc"
	Id      string        "id"
	Method  string        "method"
	Params  []interface{} "params"
}

type NMCError struct {
	Code    int    "code"
	Message string "message"
}

type ResultDetail struct {
	Value     string "value"
	Name      string "name"
	ExpiresIn int    "expires_in"
	TxId      string "txid"
}

type NMCResponse struct {
	Result []ResultDetail "result"
	Error  NMCError
	Id     string "id"
}

func nmcPOST(body *bytes.Buffer) (response *http.Response, err os.Error) {
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
	req.URL = options.nmcURL

	return client.Do(&req)
}

func namecoidRequest(data NMCData) (responseBody []byte, err os.Error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		LOG.Fatalln(err)
	}
	response, err := nmcPOST(bytes.NewBuffer(jsonData))
	if err != nil {
		LOG.Fatalln(err)
	}

	if response.StatusCode == 200 {
		reader := bufio.NewReader(response.Body)
		responseBody = make([]byte, response.ContentLength)
		reader.Read(responseBody)
	}

	return
}

type NMCValue struct {
	Ip  []string
	Ip6 []string
	Map map[string]string "map"
}

func nmcLookup(name string) (record ResultDetail, err os.Error) {
	params := make([]interface{}, 2)
	params[0] = "d/" + name
	params[1] = 1
	data := NMCData{Jsonrpc: "1.0", Id: "godns", Method: "name_scan", Params: params}
	responseBody, err := namecoidRequest(data)
	if err != nil {
		return
	}

	var response NMCResponse
	json.Unmarshal(responseBody, &response)

	if response.Error.Code == 0 {
		LOG.Println(response)
		record = response.Result[0]
	} else {
		err = os.NewError(response.Error.Message)
	}

	return // we never get here anyway
}
