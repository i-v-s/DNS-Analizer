#include "structs.h"

const char * DNSHeader::opcodes[3] = {"Query", "IQuery", "Status"};
const char * DNSHeader::rcodes[6] = {"Ok", "Format error", "Server failure", "Name error", "Not implemented", "Refused"};
