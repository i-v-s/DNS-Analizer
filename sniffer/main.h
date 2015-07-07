#include <vector>
#include <stdint.h>
#include <stdarg.h>
#include "platform.h"

class Error
{
private:
	const char * format;
	std::string message;
public:
	Error(const char * format, ...): format(format)
	{
		va_list args;
		va_start(args, format);
        char buf[256];
        vsnprintf(buf, sizeof(buf), format, args);
        message = buf;
		va_end(args);
	}
	inline bool operator == (const char * msg) const {return format == msg;};
	inline void print() const {printf(message.c_str());};
	inline const char * getFormat() const {return format;};
};

class Analizer
{
private:
	BYTE * loadDomain(std::string &dst, BYTE * src, BYTE * end, BYTE * start);
	BYTE * loadString(std::string &dst, BYTE * src, BYTE * end);
	BYTE * processRecords(BYTE * x, BYTE * end, BYTE * base, int rcount, const char * sectName);
	void testQtype(unsigned int qtype);
	void testType(unsigned int type);
	void testQclass(unsigned int qclass);
	void testClass(unsigned int _class);
public:
	int verbose;
	std::vector<Error> errors;
    bool process(BYTE * buffer, unsigned int count);
    Analizer(int verbose): verbose(verbose) {}
	void printErrors();
};
