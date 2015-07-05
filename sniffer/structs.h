#include "platform.h"

#pragma pack(push, 1)

struct IPHeader
{
	// IP
	unsigned char  ver_len;		// версия и длина заголовка
	unsigned char  tos;			// тип сервиса
	unsigned short length;		// длина всего пакета 

	unsigned short id;			// Id 
	unsigned short flgs_offset;	// смещение

	unsigned char  ttl;			// время жизни 
	unsigned char  protocol;	// протокол 
	unsigned short xsum;		// контрольная сумма 

	unsigned long  src;			// IP-адрес отправителя 
	unsigned long  dst;		    // IP-адрес назначения 
	inline void swap()
	{
		length = htons(length);
		id = htons(id);
		flgs_offset = htons(flgs_offset);
		xsum = htons(xsum);
		src = htonl(src);
		dst = htonl(dst);
	}
	inline int size() const { return (ver_len & 0xF) << 2;}
	inline int calcSum()
	{
		int sum = 0;
		for(unsigned short * p = (unsigned short *) this, * e = (unsigned short * )(((BYTE *)this) + size()); p < e; p++)
			sum += htons(*p);
		sum -= htons(xsum);
		return 0xFFFF & ~(sum + (sum >> 16));
	}
};

struct UDPHeader
{
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned short udpLen;
	unsigned short udpSum;
	inline void swap()
	{
		srcPort = htons(srcPort);
		dstPort = htons(dstPort);
		udpLen = htons(udpLen);
		udpSum = htons(udpSum);
	}
	inline int calcSum(BYTE * end)
	{
	}
};

struct DNSHeader
{
	unsigned short ID;
	unsigned short Flags;
	unsigned short QDCount, ANCount, NSCount, ARCount;
	inline void swap()
	{
		ID = htons(ID);
		Flags = htons(Flags);
		QDCount = htons(QDCount);
		ANCount = htons(ANCount);
		NSCount = htons(NSCount);
		ARCount = htons(ARCount);
	}
	inline int getQR() { return Flags & 0x8000;}
	inline int getRcode() {return Flags & 0xF;}
	inline int getOpcode() {return (Flags >> 11) & 0xF;}
	static const char * opcodes[3];
	static const char * rcodes[6];
	inline const char * getRcodeStr() 
	{
		int rc = getRcode();
		if(rc >= sizeof(rcodes) / sizeof(*rcodes)) return "?";
		return rcodes[rc];
	}
	inline const char * getOpcodeStr() 
	{
		int rc = getOpcode();
		if(rc >= sizeof(opcodes) / sizeof(*opcodes)) return "?";
		return opcodes[rc];
	}
};

#pragma pack(pop)


