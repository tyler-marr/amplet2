import struct
import socket

# TODO move to another file
class VersionMismatch(Exception):
    def __init__(self, got, expected):
	self.got = got
	self.expected = expected
    def __str__(self):
	return "%d != %d" % (self.got, self.expected)


# version needs to keep up with the version number in src/tests/icmp/icmp.h
AMP_DNS_TEST_VERSION = 2014020400

def get_data(data):
    """
    Extract the DNS test results from the data blob.

    The test result data consists of a single dns_report header_t followed
    by a number of dns_report_item_t structures with the individual test
    results. Both of these are described in src/tests/dns/dns.h
    """
    header_len = struct.calcsize("!IHHHBBB")
    item_len = struct.calcsize("!16siIIHHHHBBBB")

    # check the version number first before looking at anything else
    version, = struct.unpack_from("!I", data, 0)
    if version != AMP_DNS_TEST_VERSION:
	raise VersionMismatch(version, AMP_DNS_TEST_VERSION)
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    qtype,qclass,payload,opts,count,querylen = struct.unpack_from("!HHHBBB", data, offset)

    # get the variable length query string that follows the header
    assert(querylen > 0 and querylen < 255)
    offset = header_len
    (query,) = struct.unpack_from("!%ds" % querylen, data, offset)
    offset += querylen
    assert(querylen == len(query))

    results = []

    # extract every item in the data portion of the message
    while count > 0:
	# "p" pascal string could be useful here, length byte before string
	addr,rtt,qlen,size,ans,aut,add,flags,family,ttl,namelen,instancelen = struct.unpack_from("!16siIIHHHHBBBB", data, offset)

        # get the variable length ampname string that follows the data
        assert(namelen > 0 and namelen < 255)
        offset += item_len
        (name,) = struct.unpack_from("!%ds" % namelen, data, offset)
        offset += namelen
        assert(namelen == len(name))

        if instancelen > 0:
            # get the variable length instance string that follows the data
            assert(instancelen > 0 and instancelen < 255)
            (instance,) = struct.unpack_from("!%ds" % instancelen, data, offset)
            offset += instancelen
            assert(instancelen == len(instance))
        else:
            # otherwise no specific instance name, just use the server name
            instance = name

	if family == socket.AF_INET:
	    addr = socket.inet_ntop(family, addr[:4])
	elif family == socket.AF_INET6:
	    addr = socket.inet_ntop(family, addr)
	else:
	    #print "Unknown address family %d" % family
	    raise ValueError

	results.append(
		{
		    "destination": name.rstrip("\0"),
		    "instance": instance.rstrip("\0"),
		    "address": addr,
		    "rtt": rtt,
		    "query_len": qlen,
		    "response_size": size,
		    "total_answer": ans,
		    "total_authority": aut,
		    "total_additional": add,
		    "flags": {
			"rd": bool(flags & 0x0100),
			"tc": bool(flags & 0x0200),
			"aa": bool(flags & 0x0400),
			"opcode": get_opcode_name(flags & 0x7800),
			"qr": bool(flags & 0x8000),
			"rcode": get_rcode_name(flags & 0x000f),
			"cd": bool(flags & 0x0010),
			"ad": bool(flags & 0x0020),
			"ra": bool(flags & 0x0080),
		    },
		    "ttl": ttl,
		    }
		)
	count -= 1

    return {
	"query": query.rstrip("\0"),
	"query_type": get_query_type(qtype),
	"query_class": get_query_class(qclass),
	"udp_payload_size": payload,
	"recurse": bool(opts & 0x01),
	"dnssec": bool(opts & 0x02),
	"nsid": bool(opts & 0x04),
	"results": results,
    }

def get_query_class(qclass):
    if qclass == 0x01:
	return "IN"
    return "0x%.02x" % qclass

def get_query_type(qtype):
    if qtype == 0x01:
	return "A"
    if qtype == 0x02:
	return "NS"
    if qtype == 0x06:
	return "SOA"
    if qtype == 0x0c:
	return "PTR"
    if qtype == 0x0e:
	return "MX"
    if qtype == 0x1c:
	return "AAAA"
    if qtype == 0xff:
	return "ANY"
    return "0x%.02x" % qtype

def get_opcode_name(opcode):
    if opcode == 0:
	return "QUERY"
    if opcode == 1:
	return "IQUERY"
    if opcode == 2:
	return "STATUS"
    return "0x%.02x" % opcode

def get_rcode_name(rcode):
    if rcode == 0x0:
	return "NOERROR"
    if rcode == 0x1:
	return "FORMERR"
    if rcode == 0x2:
	return "SERVFAIL"
    if rcode == 0x3:
	return "NXDOMAIN";
    if rcode == 0x4:
	return "NOTIMP";
    if rcode == 0x5:
	return "REFUSED";
    if rcode == 0x6:
	return "YXDOMAIN";
    if rcode == 0x7:
	return "YXRRSET";
    if rcode == 0x8:
	return "NXRRSET";
    if rcode == 0x9:
	return "NOTAUTH";
    if rcode == 0xa:
	return "NOTZONE";


