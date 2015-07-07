#include "platform.h"
#include <stdint.h>

#pragma pack(push, 1)

struct IPHeader
{
	// IP
    uint8_t  ver_len;		// версия и длина заголовка
    uint8_t  tos;			// тип сервиса
    uint16_t length;		// длина всего пакета

    uint16_t id;			// Id
    uint16_t flgs_offset;	// смещение

    uint8_t  ttl;			// время жизни
    uint8_t  protocol;	// протокол
    uint16_t xsum;		// контрольная сумма

    uint32_t  src;			// IP-адрес отправителя
    uint32_t  dst;		    // IP-адрес назначения
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
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t udpLen;
    uint16_t udpSum;
	inline void swap()
	{
		srcPort = htons(srcPort);
		dstPort = htons(dstPort);
		udpLen = htons(udpLen);
		udpSum = htons(udpSum);
	}
	inline int calcSum(BYTE * end)
	{
        return 0;
	}
};

struct DNSHeader
{
    uint16_t ID;
    uint16_t Flags;
    uint16_t QDCount, ANCount, NSCount, ARCount;
	inline void swap()
	{
		ID = htons(ID);
		Flags = htons(Flags);
		QDCount = htons(QDCount);
		ANCount = htons(ANCount);
		NSCount = htons(NSCount);
		ARCount = htons(ARCount);
	}
    inline unsigned int getQR() { return Flags & 0x8000;}
    inline unsigned int getRcode() {return Flags & 0xF;}
    inline unsigned int getOpcode() {return (Flags >> 11) & 0xF;}
	static const char * opcodes[3];
	static const char * rcodes[6];
	inline const char * getRcodeStr() 
	{
        unsigned int rc = getRcode();
		if(rc >= sizeof(rcodes) / sizeof(*rcodes)) return "?";
		return rcodes[rc];
	}
	inline const char * getOpcodeStr() 
	{
        unsigned int rc = getOpcode();
		if(rc >= sizeof(opcodes) / sizeof(*opcodes)) return "?";
		return opcodes[rc];
	}
};

#pragma pack(pop)


