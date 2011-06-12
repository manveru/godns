// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS packet assembly.  See RFC 1035.

package dns

import (
	"fmt"
	"os"
	"reflect"
	"net"
)

// Packet formats

// Wire constants.
const (
	// valid RR_Header.Rrtype and Question.Qtype
	TypeA     = 1
	TypeNS    = 2
	TypeMD    = 3
	TypeMF    = 4
	TypeCNAME = 5
	TypeSOA   = 6
	TypeMB    = 7
	TypeMG    = 8
	TypeMR    = 9
	TypeNULL  = 10
	TypeWKS   = 11
	TypePTR   = 12
	TypeHINFO = 13
	TypeMINFO = 14
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33

	// valid Question.Qtype only
	TypeAXFR  = 252
	TypeMAILB = 253
	TypeMAILA = 254
	TypeALL   = 255

	// valid Question.qclass
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassANY    = 255

	// Msg.rcode
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// The wire format for the DNS packet header.
type Header struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
)

// DNS queries.
type Question struct {
	Name   string "domain-name" // "domain-name" specifies encoding; see packers below
	Qtype  uint16
	Qclass uint16
}

// DNS responses (resource records).
// There are many types of messages,
// but they all share the same header.
type RR_Header struct {
	Name     string "domain-name"
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16 // length of data after header
}

func (h *RR_Header) Header() *RR_Header {
	return h
}

type RR interface {
	Header() *RR_Header
}

// Specific DNS RR formats for each query type.

type RR_CNAME struct {
	Hdr   RR_Header
	Cname string "domain-name"
}

func (rr *RR_CNAME) Header() *RR_Header {
	return &rr.Hdr
}

type RR_HINFO struct {
	Hdr RR_Header
	Cpu string
	Os  string
}

func (rr *RR_HINFO) Header() *RR_Header {
	return &rr.Hdr
}

type RR_MB struct {
	Hdr RR_Header
	Mb  string "domain-name"
}

func (rr *RR_MB) Header() *RR_Header {
	return &rr.Hdr
}

type RR_MG struct {
	Hdr RR_Header
	Mg  string "domain-name"
}

func (rr *RR_MG) Header() *RR_Header {
	return &rr.Hdr
}

type RR_MINFO struct {
	Hdr   RR_Header
	Rmail string "domain-name"
	Email string "domain-name"
}

func (rr *RR_MINFO) Header() *RR_Header {
	return &rr.Hdr
}

type RR_MR struct {
	Hdr RR_Header
	Mr  string "domain-name"
}

func (rr *RR_MR) Header() *RR_Header {
	return &rr.Hdr
}

type RR_MX struct {
	Hdr  RR_Header
	Pref uint16
	Mx   string "domain-name"
}

func (rr *RR_MX) Header() *RR_Header {
	return &rr.Hdr
}

type RR_NS struct {
	Hdr RR_Header
	Ns  string "domain-name"
}

func (rr *RR_NS) Header() *RR_Header {
	return &rr.Hdr
}

type RR_PTR struct {
	Hdr RR_Header
	Ptr string "domain-name"
}

func (rr *RR_PTR) Header() *RR_Header {
	return &rr.Hdr
}

type RR_SOA struct {
	Hdr     RR_Header
	Ns      string "domain-name"
	Mbox    string "domain-name"
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

func (rr *RR_SOA) Header() *RR_Header {
	return &rr.Hdr
}

type RR_TXT struct {
	Hdr RR_Header
	Txt string // not domain name
}

func (rr *RR_TXT) Header() *RR_Header {
	return &rr.Hdr
}

type RR_SRV struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string "domain-name"
}

func (rr *RR_SRV) Header() *RR_Header {
	return &rr.Hdr
}

type RR_A struct {
	Hdr RR_Header
	A   uint32 "ipv4"
}

func (rr *RR_A) Header() *RR_Header {
	return &rr.Hdr
}

type RR_AAAA struct {
	Hdr  RR_Header
	AAAA [16]byte "ipv6"
}

func (rr *RR_AAAA) Header() *RR_Header {
	return &rr.Hdr
}

// Packing and unpacking.
//
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

// Map of constructors for each RR wire type.
var rr_mk = map[int]func() RR{
	TypeCNAME: func() RR { return new(RR_CNAME) },
	TypeHINFO: func() RR { return new(RR_HINFO) },
	TypeMB:    func() RR { return new(RR_MB) },
	TypeMG:    func() RR { return new(RR_MG) },
	TypeMINFO: func() RR { return new(RR_MINFO) },
	TypeMR:    func() RR { return new(RR_MR) },
	TypeMX:    func() RR { return new(RR_MX) },
	TypeNS:    func() RR { return new(RR_NS) },
	TypePTR:   func() RR { return new(RR_PTR) },
	TypeSOA:   func() RR { return new(RR_SOA) },
	TypeTXT:   func() RR { return new(RR_TXT) },
	TypeSRV:   func() RR { return new(RR_SRV) },
	TypeA:     func() RR { return new(RR_A) },
	TypeAAAA:  func() RR { return new(RR_AAAA) },
}

// Pack a domain name s into msg[off:].
// Domain names are a sequence of counted strings
// split at the dots.  They end with a zero-length string.
func packDomainName(s string, msg []byte, off int) (off1 int, ok bool) {
	// Add trailing dot to canonicalize name.
	if n := len(s); n == 0 || s[n-1] != '.' {
		s += "."
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// There is also a trailing zero.
	// Check that we have all the space we need.
	tot := len(s) + 1
	if off+tot > len(msg) {
		return len(msg), false
	}

	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return len(msg), false
			}
			msg[off] = byte(i - begin)
			off++
			for j := begin; j < i; j++ {
				msg[off] = s[j]
				off++
			}
			begin = i + 1
		}
	}
	msg[off] = 0
	off++
	return off, true
}

// Unpack a domain name.
// In addition to the simple sequences of counted strings above,
// domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning
// many entries in a single domain.  The pointers are marked
// by a length byte with the top two bits set.  Ignoring those
// two bits, that byte and the next give a 14 bit offset from msg[0]
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet,
// we return off1 == the offset after the first pointer we found,
// which is where the next record will start.
// In theory, the pointers are only allowed to jump backward.
// We let them jump anywhere and stop jumping after a while.
func unpackDomainName(msg []byte, off int) (s string, off1 int, ok bool) {
	s = ""
	ptr := 0 // number of pointers followed
Loop:
	for {
		if off >= len(msg) {
			return "", len(msg), false
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// end of name
				break Loop
			}
			// literal string
			if off+c > len(msg) {
				return "", len(msg), false
			}
			s += string(msg[off:off+c]) + "."
			off += c
		case 0xC0:
			// pointer to somewhere else in msg.
			// remember location after first ptr,
			// since that's how many bytes we consumed.
			// also, don't follow too many pointers --
			// maybe there's a loop.
			if off >= len(msg) {
				return "", len(msg), false
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			if ptr++; ptr > 10 {
				return "", len(msg), false
			}
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return "", len(msg), false
		}
	}
	if ptr == 0 {
		off1 = off
	}
	return s, off1, true
}

// Pack a reflect.StructValue into msg.  Struct members can only be uint16, uint32, string,
// [n]byte, and other (often anonymous) structs.
func packStructValue(val reflect.Value, msg []byte, off int) (off1 int, ok bool) {
	for i := 0; i < val.NumField(); i++ {
		f := val.Type().Field(i)
		switch fv := val.Field(i); fv.Kind() {
		default:
		BadType:
			fmt.Fprintf(os.Stderr, "net: dns: unknown packing type %v", f.Type)
			return len(msg), false
		case reflect.Struct:
			off, ok = packStructValue(fv, msg, off)
		case reflect.Uint16:
			if off+2 > len(msg) {
				return len(msg), false
			}
			i := fv.Uint()
			msg[off] = byte(i >> 8)
			msg[off+1] = byte(i)
			off += 2
		case reflect.Uint32:
			if off+4 > len(msg) {
				return len(msg), false
			}
			i := fv.Uint()
			msg[off] = byte(i >> 24)
			msg[off+1] = byte(i >> 16)
			msg[off+2] = byte(i >> 8)
			msg[off+3] = byte(i)
			off += 4
		case reflect.Array:
			if fv.Type().Elem().Kind() != reflect.Uint8 {
				goto BadType
			}
			n := fv.Len()
			if off+n > len(msg) {
				return len(msg), false
			}
			reflect.Copy(reflect.ValueOf(msg[off:off+n]), fv)
			off += n
		case reflect.String:
			// There are multiple string encodings.
			// The tag distinguishes ordinary strings from domain names.
			s := fv.String()
			switch f.Tag {
			default:
				fmt.Fprintf(os.Stderr, "net: dns: unknown string tag %v", f.Tag)
				return len(msg), false
			case "domain-name":
				off, ok = packDomainName(s, msg, off)
				if !ok {
					return len(msg), false
				}
			case "":
				// Counted string: 1 byte length.
				if len(s) > 255 || off+1+len(s) > len(msg) {
					return len(msg), false
				}
				msg[off] = byte(len(s))
				off++
				off += copy(msg[off:], s)
			}
		}
	}
	return off, true
}

func structValue(any interface{}) reflect.Value {
	return reflect.ValueOf(any).Elem()
}

func packStruct(any interface{}, msg []byte, off int) (off1 int, ok bool) {
	off, ok = packStructValue(structValue(any), msg, off)
	return off, ok
}

// Unpack a reflect.StructValue from msg.
// Same restrictions as packStructValue.
func unpackStructValue(val reflect.Value, msg []byte, off int) (off1 int, ok bool) {
	for i := 0; i < val.NumField(); i++ {
		f := val.Type().Field(i)
		switch fv := val.Field(i); fv.Kind() {
		default:
		BadType:
			fmt.Fprintf(os.Stderr, "net: dns: unknown packing type %v", f.Type)
			return len(msg), false
		case reflect.Struct:
			off, ok = unpackStructValue(fv, msg, off)
		case reflect.Uint16:
			if off+2 > len(msg) {
				return len(msg), false
			}
			i := uint16(msg[off])<<8 | uint16(msg[off+1])
			fv.SetUint(uint64(i))
			off += 2
		case reflect.Uint32:
			if off+4 > len(msg) {
				return len(msg), false
			}
			i := uint32(msg[off])<<24 | uint32(msg[off+1])<<16 | uint32(msg[off+2])<<8 | uint32(msg[off+3])
			fv.SetUint(uint64(i))
			off += 4
		case reflect.Array:
			if fv.Type().Elem().Kind() != reflect.Uint8 {
				goto BadType
			}
			n := fv.Len()
			if off+n > len(msg) {
				return len(msg), false
			}
			reflect.Copy(fv, reflect.ValueOf(msg[off:off+n]))
			off += n
		case reflect.String:
			var s string
			switch f.Tag {
			default:
				fmt.Fprintf(os.Stderr, "net: dns: unknown string tag %v", f.Tag)
				return len(msg), false
			case "domain-name":
				s, off, ok = unpackDomainName(msg, off)
				if !ok {
					return len(msg), false
				}
			case "":
				if off >= len(msg) || off+1+int(msg[off]) > len(msg) {
					return len(msg), false
				}
				n := int(msg[off])
				off++
				b := make([]byte, n)
				for i := 0; i < n; i++ {
					b[i] = msg[off+i]
				}
				off += n
				s = string(b)
			}
			fv.SetString(s)
		}
	}
	return off, true
}

func unpackStruct(any interface{}, msg []byte, off int) (off1 int, ok bool) {
	off, ok = unpackStructValue(structValue(any), msg, off)
	return off, ok
}

// Generic struct printer.
// Doesn't care about the string tag "domain-name",
// but does look for an "ipv4" tag on uint32 variables
// and the "ipv6" tag on array variables,
// printing them as IP addresses.
func printStructValue(val reflect.Value) string {
	s := "{"
	for i := 0; i < val.NumField(); i++ {
		if i > 0 {
			s += ", "
		}
		f := val.Type().Field(i)
		if !f.Anonymous {
			s += f.Name + "="
		}
		fval := val.Field(i)
		if fv := fval; fv.Kind() == reflect.Struct {
			s += printStructValue(fv)
		} else if fv := fval; (fv.Kind() == reflect.Uint || fv.Kind() == reflect.Uint8 || fv.Kind() == reflect.Uint16 || fv.Kind() == reflect.Uint32 || fv.Kind() == reflect.Uint64 || fv.Kind() == reflect.Uintptr) && f.Tag == "ipv4" {
			i := fv.Uint()
			s += net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i)).String()
		} else if fv := fval; fv.Kind() == reflect.Array && f.Tag == "ipv6" {
			i := fv.Interface().([]byte)
			s += net.IP(i).String()
		} else {
			s += fmt.Sprint(fval.Interface())
		}
	}
	s += "}"
	return s
}

func printStruct(any interface{}) string { return printStructValue(structValue(any)) }

// Resource record packer.
func packRR(rr RR, msg []byte, off int) (off2 int, ok bool) {
	var off1 int
	// pack twice, once to find end of header
	// and again to find end of packet.
	// a bit inefficient but this doesn't need to be fast.
	// off1 is end of header
	// off2 is end of rr
	off1, ok = packStruct(rr.Header(), msg, off)
	off2, ok = packStruct(rr, msg, off)
	if !ok {
		return len(msg), false
	}
	// pack a third time; redo header with correct data length
	rr.Header().Rdlength = uint16(off2 - off1)
	packStruct(rr.Header(), msg, off)
	return off2, true
}

// Resource record unpacker.
func unpackRR(msg []byte, off int) (rr RR, off1 int, ok bool) {
	// unpack just the header, to find the rr type and length
	var h RR_Header
	off0 := off
	if off, ok = unpackStruct(&h, msg, off); !ok {
		return nil, len(msg), false
	}
	end := off + int(h.Rdlength)

	// make an rr of that type and re-unpack.
	// again inefficient but doesn't need to be fast.
	mk, known := rr_mk[int(h.Rrtype)]
	if !known {
		return &h, end, true
	}
	rr = mk()
	off, ok = unpackStruct(rr, msg, off0)
	if off != end {
		return &h, end, true
	}
	return rr, off, ok
}

// Usable representation of a DNS packet.

// A manually-unpacked version of (id, bits).
// This is in its own struct for easy printing.
type MsgHdr struct {
	Id                  uint16
	Response            bool
	Opcode              int
	Authoritative       bool
	Truncated           bool
	Recursion_desired   bool
	Recursion_available bool
	Rcode               int
}

type Msg struct {
	MsgHdr
	Question []Question
	Answer   []RR
	ns       []RR
	extra    []RR
}

func (dns *Msg) Pack() (msg []byte, ok bool) {
	var dh Header

	// Convert convenient Msg into wire-like Header.
	dh.Id = dns.Id
	dh.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode)
	if dns.Recursion_available {
		dh.Bits |= _RA
	}
	if dns.Recursion_desired {
		dh.Bits |= _RD
	}
	if dns.Truncated {
		dh.Bits |= _TC
	}
	if dns.Authoritative {
		dh.Bits |= _AA
	}
	if dns.Response {
		dh.Bits |= _QR
	}

	// Prepare variable sized arrays.
	question := dns.Question
	answer := dns.Answer
	ns := dns.ns
	extra := dns.extra

	dh.Qdcount = uint16(len(question))
	dh.Ancount = uint16(len(answer))
	dh.Nscount = uint16(len(ns))
	dh.Arcount = uint16(len(extra))

	// Could work harder to calculate message size,
	// but this is far more than we need and not
	// big enough to hurt the allocator.
	msg = make([]byte, 2000)

	// Pack it in: header and then the pieces.
	off := 0
	off, ok = packStruct(&dh, msg, off)
	for i := 0; i < len(question); i++ {
		off, ok = packStruct(&question[i], msg, off)
	}
	for i := 0; i < len(answer); i++ {
		off, ok = packRR(answer[i], msg, off)
	}
	for i := 0; i < len(ns); i++ {
		off, ok = packRR(ns[i], msg, off)
	}
	for i := 0; i < len(extra); i++ {
		off, ok = packRR(extra[i], msg, off)
	}
	if !ok {
		return nil, false
	}
	return msg[0:off], true
}

func (dns *Msg) Unpack(msg []byte) bool {
	// Header.
	var dh Header
	off := 0
	var ok bool
	if off, ok = unpackStruct(&dh, msg, off); !ok {
		return false
	}
	dns.Id = dh.Id
	dns.Response = (dh.Bits & _QR) != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = (dh.Bits & _AA) != 0
	dns.Truncated = (dh.Bits & _TC) != 0
	dns.Recursion_desired = (dh.Bits & _RD) != 0
	dns.Recursion_available = (dh.Bits & _RA) != 0
	dns.Rcode = int(dh.Bits & 0xF)

	// Arrays.
	dns.Question = make([]Question, dh.Qdcount)
	dns.Answer = make([]RR, 0, dh.Ancount)
	dns.ns = make([]RR, 0, dh.Nscount)
	dns.extra = make([]RR, 0, dh.Arcount)

	var rec RR

	for i := 0; i < len(dns.Question); i++ {
		off, ok = unpackStruct(&dns.Question[i], msg, off)
	}
	for i := 0; i < int(dh.Ancount); i++ {
		rec, off, ok = unpackRR(msg, off)
		if !ok {
			return false
		}
		dns.Answer = append(dns.Answer, rec)
	}
	for i := 0; i < int(dh.Nscount); i++ {
		rec, off, ok = unpackRR(msg, off)
		if !ok {
			return false
		}
		dns.ns = append(dns.ns, rec)
	}
	for i := 0; i < int(dh.Arcount); i++ {
		rec, off, ok = unpackRR(msg, off)
		if !ok {
			return false
		}
		dns.extra = append(dns.extra, rec)
	}
	//	if off != len(msg) {
	//		println("extra bytes in dns packet", off, "<", len(msg));
	//	}
	return true
}

func (dns *Msg) String() string {
	s := "DNS: " + printStruct(&dns.MsgHdr) + "\n"
	if len(dns.Question) > 0 {
		s += "-- Questions\n"
		for i := 0; i < len(dns.Question); i++ {
			s += printStruct(&dns.Question[i]) + "\n"
		}
	}
	if len(dns.Answer) > 0 {
		s += "-- Answers\n"
		for i := 0; i < len(dns.Answer); i++ {
			s += printStruct(dns.Answer[i]) + "\n"
		}
	}
	if len(dns.ns) > 0 {
		s += "-- Name servers\n"
		for i := 0; i < len(dns.ns); i++ {
			s += printStruct(dns.ns[i]) + "\n"
		}
	}
	if len(dns.extra) > 0 {
		s += "-- Extra\n"
		for i := 0; i < len(dns.extra); i++ {
			s += printStruct(dns.extra[i]) + "\n"
		}
	}
	return s
}
