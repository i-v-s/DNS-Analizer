// sniffer.cpp : Defines the entry point for the console application.
//
//#include "stdafx.h"
#include <stdio.h>
#include <string.h>
//#include <codecvt>
#include <map>
#include <set>
#include <unordered_set>

#include "structs.h"
#include "platform.h"
#include "main.h"


inline bool InitializeSockets()
{
    #if PLATFORM == PLATFORM_WINDOWS
    WSADATA WsaData;
    return WSAStartup( MAKEWORD(2,2), &WsaData ) == NO_ERROR;
    #else
    return true;
    #endif
}

inline void ShutdownSockets()
{
    #if PLATFORM == PLATFORM_WINDOWS
    WSACleanup();
    #endif
}

SOCKET rawSock = INVALID_SOCKET;

void Analizer::printErrors()
{
	if(!errors.empty())
	{
		printf("\n!!! Found errors:");
        for(std::vector<Error>::iterator i = errors.begin(); i != errors.end(); i++)
		{
			printf("\n >> ");
			i->print();
		}
		errors.clear();
	}
}


bool CreateRAW()
{
    //#define SIO_RCV_ALL 0x98000001
	rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP); // IPv4, RAW, UDP
	//s = WSASocket(AF_INET, SOCK_RAW, IPPROTO_UDP, 0, 0, 0); // IPv4, RAW, UDP
	if(rawSock == INVALID_SOCKET)
	{
        int le = errno;
        printf("\nFailed to create RAW socket(error:%d)", le);
        if(le == 10013 || le == 1) printf("\nThis program must be run under administrator");
		return false;
	}
	char hm[128];
	gethostname(hm, sizeof(hm));
    HOSTENT * hi = gethostbyname(hm);

    SOCKADDR_IN dest;
    memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = ((struct in_addr *)hi->h_addr_list[0])->s_addr;


	if(bind(rawSock, (SOCKADDR *) &dest, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
        printf("\nFailed to bind RAW socket(error:%d)\n", errno);
		return false;
	}

    /*int timeout = 1000;
	if(setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == SOCKET_ERROR)
	{
        printf("\nFailed to set timeout for RAW socket(error:%d)\n", errno);
		return false;
    }*/
	//RCVALL_VALUE v = RCVALL_ON;
	//DWORD in;
#if PLATFORM == PLATFORM_WINDOWS

	u_long v = 1;
	//if(WSAIoctl(s, SIO_RCVALL, &v, sizeof(v), NULL, 0, &in, 0, 0) == SOCKET_ERROR)
    if(ioctlsocket(rawSock, SIO_RCVALL, &v) == SOCKET_ERROR)
	{
        printf("\nFailed to enable receive all(error:%d)\n", errno);
		return false;
	}
#endif
	/*if(ioctlsocket(s, SIO_RCVALL, &RS_Flag) == SOCKET_ERROR) // socket, 
	{
		printf("failed to create RAW socket(error:%d)\n", WSAGetLastError());
		return false;
	}*/
	return true;
}

#define MAX_PACKET_SIZE    0x10000

BYTE buffer[MAX_PACKET_SIZE];


void printHost(unsigned int host)
{
	//printf("%d.%d.%d.%d:%d", (host >> 24) & 255, (host >> 16) & 255, (host >> 8) & 255, host & 255, port);
	printf("%d.%d.%d.%d", (host >> 24) & 255, (host >> 16) & 255, (host >> 8) & 255, host & 255);
}

#define DNS_PORT 53


const char 
	* eUEP			= "Unexpected end of packet",
	* eWrongSymbol	= "Wrong symbol in domain label found: %s",
	* eTooLong		= "Too long(%d) domain name: %s",
	* eTooOffsets	= "Too many offsets in domain name",
	* eWrongLen		= "Wrong length/offset(%d) in domain name",
	* eOpcode		= "Unknown OPCODE %d",
	* eRcode		= "Unknown RCODE %d";

BYTE * Analizer::loadString(std::string &dst, BYTE * src, BYTE * end)
{
	if(src >= end) { errors.push_back(eUEP); return 0;}
	int l = *(src++);
	if(src + l > end) { errors.push_back(eUEP); return 0;}
	dst.append((char *)src, l);
	return src + l;
}

BYTE * Analizer::loadDomain(std::string &dst, BYTE * src, BYTE * end, BYTE * start)
{
	if(src >= end) { errors.push_back(eUEP); return 0;}
	dst = "";
	bool error = false;
	BYTE * result = 0;
	int total = 0, pc = 50;
	while(total < 500)
	{
		int l = *(src++);
		switch(l & 0xC0)
		{
		case 0xC0:
			{
				int o = ((l & 0x3) << 8) | *(src++);
				if(!result) result = src;
				src = start + o;
			}
			if(!--pc)
			{
				errors.push_back(Error(eTooOffsets, dst.c_str()));
				return result;
			}			
			continue;
		case 0x80:
		case 0x40:
			errors.push_back(Error(eWrongLen, l));
			return result;
		}

		if(!l) 
		{
			if(error) errors.push_back(Error(eWrongSymbol, dst.c_str()));
			if(total >= 255) errors.push_back(Error(eTooLong, total, dst.c_str()));
			return result ? result : src;
		}
		total += l + 1;
		if(src + l > end) { errors.push_back(eUEP); return 0;}
		if(!dst.empty()) dst.append(".");
		dst.append((char *)src, l);
		char c = *(src++);
		if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) error = true;

		while(--l)
		{
			c = *(src++);
			if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
			if(c != '-' || l <= 1) error = true;
		}
	}
	errors.push_back(Error(eTooLong, total, dst.c_str()));
	return 0;
}

const char * types[33] =
	{"A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT", 
	 "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR", "SIG", "KEY", 0, "GPOS", "AAAA", "LOC", "NXT", 0, 0, "SRV"};
const char * qtypes[4] = // 252 - 255
	{"AXFR", "MAILB", "MAILA", "*"};
const char * classes[4] = // 1 - 4
	{"IN", "CS", "CH", "HS"};


BYTE * Analizer::processRecords(BYTE * x, BYTE * end, BYTE * base, int rcount, const char * sectName)
{
    int pref;
	std::string name;
	for(int it = 1; it <= rcount; it++)
	{
		x = loadDomain(name, x, end, base);
		if(verbose > 1) printf("\n  %s: %s", sectName, name.c_str());
		if(!x) return 0;
		if(x + 10 > end) { errors.push_back(eUEP); return 0;}
		int type = (x[0] << 8) | x[1];
		testType(type);
		testClass((x[2] << 8) | x[3]);
		int ttl = (x[4] << 24) | (x[5] << 16) | (x[6] << 8) | x[7];
        if(ttl <= 0) errors.push_back(Error("TTL must be positive in section %s #%d", sectName, it));
		int rdlen = (x[8] << 8) | x[9];
		x += 10;
		if(x + rdlen > end) { errors.push_back("Unexpected end of packet or wrong RDLEN"); return 0;}
		BYTE * t = x;
		name = "";
		switch(type)
		{
		case 1: // A
			pref = (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3];
			if(verbose > 1) {printf(" "); printHost(pref);}
			t = x + 4;
			break;
		case 3:// MD - Obsolete
		case 4:// MF - Obsolete
			errors.push_back(Error("Type %s is obsolete", types[type - 1]));
		case 2: // NS
		case 5: // CNAME
		case 7: // MB
		case 8: // MG
		case 9: // MR
		case 12: // PTR
			t = loadDomain(name, x, end, base);
			if(verbose > 1) printf(" %s", name.c_str());
			if(!t) return 0;
			break;
		/*case 12: // PTR
			t = loadDomain(name, x, end, base, 1);
			if(verbose > 1) printf(" %s", name.c_str());
			if(!t) return 0;
			break;*/
		case 13: // HINFO
			name = " CPU:";
			t = loadString(name, x, end);
			if(!t) return 0;
			name += " OS:";
			t = loadString(name, t, end);
            if(verbose > 1) std::cout << name;
			if(!t) return 0;
			break;
		case 14: // MINFO
			t = loadDomain(name, x, end, base);
			if(verbose > 1) printf(" %s", name.c_str());
			if(!t) return 0;
			t = loadDomain(name, t, end, base);
			if(verbose > 1) printf(" %s", name.c_str());
			if(!t) return 0;
			break;
		case 15: // MX
			pref = (x[0] << 8) | x[1];
			t = loadDomain(name, x + 2, end, base);
			if(verbose > 1) printf(" pref:%d %s", pref, name.c_str());
			if(!t) return 0;
			break;
		case 16: // TXT
			for(t = x; t < x + rdlen; )
			{
				t = loadString(name, t, end);
				if(verbose > 1) printf(" %s", name.c_str());
				if(!t) return 0;
			}
			break;
		case 28: // AAAA
			if(verbose > 1)
			{
				printf(" %x:%x", (x[0] << 8) | x[1], (x[2] << 8) | x[3]);
				for(BYTE * k = x + 4; k < x + 16; k += 2)
				{
					int kk = (k[0] << 8) | k[1];
					printf(kk ? ":%x" : ":", kk);
				}
			}
			t = x + 16;
			break;
		case 10: // NULL
		default:
			t = x + rdlen;
			break;
		}
		x += rdlen;
		if(t != x) errors.push_back(Error("Error in section %s #%d, rdlen = %d, actual size = %d", sectName, it, rdlen, t - (x - rdlen)));
	}
	return x;
}


void Analizer::testType(unsigned int type)
{
	if(type >= 1 && type <= sizeof(types) / sizeof(*types) && types[type - 1])
	{
		if(verbose > 1) printf(" %s", types[type - 1]);
	}
	else if(type == 28)
	{
		if(verbose > 1) printf(" AAAA");
	}
	else errors.push_back(Error("Unknown TYPE %d", type));
}

void Analizer::testQtype(unsigned int qtype)
{
	if(qtype >= 1 && qtype <= sizeof(types) / sizeof(*types) && types[qtype - 1])
	{
		if(verbose > 1) printf(" %s", types[qtype - 1]);
	}
	else if(qtype >= 252 && qtype <= 255)
	{
		if(verbose > 1) printf(" %s", qtypes[qtype - 252]);
	} 
	else if(qtype == 28)
	{
		if(verbose > 1) printf(" AAAA");
	}
	else errors.push_back(Error("Unknown QTYPE %d", qtype));
}

void Analizer::testQclass(unsigned int qclass)
{
	if(qclass == 255)
	{
		if(verbose > 1) printf(" *");
	}
	else if(qclass >= 1 && qclass <= 4)
	{
		if(verbose > 1) printf(" %s", classes[qclass - 1]);
		return;
	}
	else errors.push_back(Error("Unknown QCLASS %d", qclass));
}

void Analizer::testClass(unsigned int _class)
{
	if(_class >= 1 && _class <= 4)
	{
		if(verbose > 1) printf(" %s", classes[_class - 1]);
		return;
	}
	else errors.push_back(Error("Unknown QCLASS %d", _class));
}


bool Analizer::process(BYTE * buffer, unsigned int count)
{
	std::string name;
	if(count < sizeof(IPHeader) + sizeof(UDPHeader)) return false;
	BYTE * x = buffer, * end = buffer + count;

	IPHeader &ip = *(IPHeader *)buffer;
	int ipHeadSize = ip.size();
	if(ipHeadSize < 20) return false;
	int ipSum = ip.calcSum();
	ip.swap();
	if(ip.flgs_offset & 0xBFFF) return false; // Игнорируем фрагментированные пакеты
	x += ipHeadSize;
	UDPHeader &udp = *(UDPHeader *) x;
	udp.swap();
	if(ip.protocol != 17 || (udp.dstPort != DNS_PORT && udp.srcPort != DNS_PORT)) return false;
	if(ipSum != ip.xsum) errors.push_back(Error("IP header has incorrect checksum 0x%.4X, calculated 0x%.4X", ip.xsum, ipSum));
	/*if(udp.udpSum)
	{
		int udpSum = udp.calcSum(end);
		if(udpSum != udp.udpSum)
			errors.push_back(Error("UDP header has incorrect checksum 0x%.4X, calculated 0x%.4X", udp.udpSum, udpSum));
	}*/
	x += sizeof(UDPHeader);
	DNSHeader &dns = *(DNSHeader *)x;
	dns.swap();

	if(count < ip.length) errors.push_back(Error("Wrong packet size %d, iplen %d", count, ip.length));
	if(ip.length != ipHeadSize + udp.udpLen) errors.push_back(Error("iplen(%d) != iphlen(%d) + udplen(%d)", ip.length, ipHeadSize, udp.udpLen));
	if(udp.udpLen - sizeof(UDPHeader) >= 512) errors.push_back(Error("udplen(%d) too much", udp.udpLen));

	if(verbose)
	{
		printf("\n0x%x from ", dns.ID);
        printHost(ip.src);
		printf(" to ");
        printHost(ip.dst);
	}

	if(dns.getOpcode() > 2) errors.push_back(Error(eOpcode, dns.getOpcode()));
	if(dns.getQR() && dns.getRcode() > 5) errors.push_back(Error(eRcode, dns.getOpcode()));

	if(verbose)
	{
		printf(" %s", dns.getOpcodeStr());
		if(dns.getQR()) printf(" response %s", dns.getRcodeStr());
	}
	//printf(" QD:%d AN:%d NS:%d AR:%d", dns.QDCount, dns.ANCount, dns.NSCount, dns.ARCount);

	if(verbose > 1) printf("\n  Packet size:%d iphlen:%d iplen:%d udplen:%d", count, ipHeadSize, ip.length, udp.udpLen);
	x += sizeof(DNSHeader);
	for(unsigned int qd = dns.QDCount; qd--; )
	{
		x = loadDomain(name, x, end, (BYTE *) &dns);
		if(verbose) printf("\n  Question: %s", name.c_str());
		if(!x) return false;
		if(x + 4 > end) { errors.push_back(eUEP); return false;}
		testQtype((x[0] << 8) | x[1]);
		testQclass((x[2] << 8) | x[3]);
		x += 4;
	}
	x = processRecords(x, end, (BYTE *) &dns, dns.ANCount, "Answer");
	if(!x) return false;
	x = processRecords(x, end, (BYTE *) &dns, dns.NSCount, "Authority");
	if(!x) return false;
	x = processRecords(x, end, (BYTE *) &dns, dns.ARCount, "Additional");
	if(!x) return false;
	if(x != end) errors.push_back(Error("Last pos(%.4X) is not equal to end pos(%.4X)", x - buffer, end - buffer));
	return true;
}

volatile bool work = true;

THREADPROC recvThread(void * ptr)
{
	Analizer a(ptr ? 2 : 1);
	printf("\nWaiting for packets... press ESC to quit");
	while(work)
	{
		int count = recv(rawSock, (char *)buffer, sizeof(buffer), 0);
		if(count == SOCKET_ERROR)
		{
            int e = errno;
			if(e == 10060) continue;
			printf("recv failed(error: %d)", e);
		}
		a.process(buffer, count);
		a.printErrors();
	}
	ShutdownSockets();
	return 0;
}

THREADPROC testThread(void * ptr)
{
	Analizer a(ptr ? 2 : 1);
	printf("\nWaiting for packet for test... press ESC to quit");
	BYTE bcopy[MAX_PACKET_SIZE];
	typedef std::set<const char *> mlist;
	std::map<int, mlist> map;
	while(work)
	{
		int count = recv(rawSock, (char *)buffer, sizeof(buffer), 0);
		if(count == SOCKET_ERROR)
		{
            int e = errno;
			if(e == 10060) continue;
			printf("\nrecv failed(error: %d)", e);
		}
		memcpy(bcopy, buffer, count);
		a.verbose = ptr ? 2 : 1;
		if(a.process(buffer, count) && a.errors.empty()) // Пока всё хорошо
		{
            std::unordered_set<const char *> set;
			a.verbose = 0;
			printf("\nTest started, count = %d\n", count);
			for(int x = 300; --x;)
			{
				int pos = rand() % count;
				BYTE val = (BYTE) rand();
				printf("[%d]=0x%.2X; ", pos, val);
				bcopy[pos] = val;
				if(x < 200)
				{
					count += (rand() & 63) - 32;
					if(count < 10) count = 10;
					if(count > 10000) count = 10000;
				}
				memcpy(buffer, bcopy, count);
				a.process(buffer, count);
				for(std::vector<Error>::iterator i = a.errors.begin(); i != a.errors.end(); i++)
				{
					const char * f = i->getFormat();
					if(set.find(f) == set.end())
					{
						printf("\n ++ ");
						i->print();
						printf("\n");
						set.insert(f);
						std::map<int, mlist>::iterator msgs = map.find(pos);
						if(msgs == map.end())
						{
							mlist ml;
							ml.insert(f);
							map.insert(std::pair<int, mlist>(pos, ml));
						} else msgs->second.insert(f);
					}
				}
				a.errors.clear();
			}
			printf("\nTest completed, count = %d", count);
			continue;
		}
		a.printErrors();
	}
	ShutdownSockets();
    std::cout << "\nTest map (packet offset - message):";
	for(std::map<int, mlist>::iterator it = map.begin(); it != map.end(); it++)
		for(mlist::iterator it1 = it->second.begin(); it1 != it->second.end(); it1++)
		{
			printf("\n%.4X - %s", it->first, *it1);
		}
	return 0;
}

int main(int argc, TCHAR* argv[])
{
	printf("DNS Packet Analizer");
	if(argc <= 1)
	{
		printf("\nAvailable options:");
		printf("\n    -v     Verbose output");
		printf("\n    -t     Make internal tests");
		printf("\n    <file> Analize frame from binary file");
	}
	bool test = false, verb = false;
    std::vector<std::basic_string<TCHAR> > fnames;
	for(int x = 1; x < argc; x++)
	{
        TCHAR * arg = argv[x];
		if(!_tcscmp(arg, _T("-t"))) 
			test = true;
		else if(!_tcscmp(arg, _T("-v"))) 
			verb = true;
		else if(arg[0] != '-') 
			fnames.push_back(arg);
		else _tprintf(_T("\nUnknown key %s"), arg);
	}

	if(!fnames.empty()) for(auto it = fnames.begin(); it != fnames.end(); it++)
	{
        ;
		_tprintf(_T("\n\nAnalizing file %s"), it->c_str());
        FILE * f = fopen(it->c_str(), _T("rb"));
        if(!f)
		{
            _tprintf(_T("\nUnable to open file %s, error %d"), it->c_str(), errno);
			continue;
		}
		int count = fread(buffer, 1, sizeof(buffer), f);
		if(int e = ferror(f)) _tprintf(_T("\nError reading file %s, error %d"), it->c_str(), e);
		fclose(f);
		if(count > 20)
		{
			printf(" loaded %d", count);
			Analizer a(verb ? 2 : 1);
			a.process(buffer + 14, count - 14);
			a.printErrors();
		}
	}
	else
	{
		InitializeSockets();
		if(!CreateRAW()) return false;
        pthread_t h = createThread(test ? testThread : recvThread, (void *)verb);
        if(!h) return 0;
		//uintptr_t t = _beginthread(recvThread, 0, (void *)verb);
		while(_getch() != 27);
        work = false;
        closesocket(rawSock);
        waitThread(h);
	}
	return 0;
}

