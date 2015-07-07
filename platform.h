
// platform detection

#define PLATFORM_WINDOWS  1
#define PLATFORM_MAC      2
#define PLATFORM_UNIX     3

#if defined(_WIN32)
#define PLATFORM PLATFORM_WINDOWS
#elif defined(__APPLE__)
#define PLATFORM PLATFORM_MAC
#else
#define PLATFORM PLATFORM_UNIX
#endif

#if PLATFORM == PLATFORM_WINDOWS

    #include <winsock2.h>
	#include <MSTcpIP.h>
    #define errno (WSAGetLastError())
    #define waitThread(h) WaitForSingleObject(h, INFINITE)
    #define THREADPROC DWORD WINAPI
    #define pthread_t HANDLE
#elif PLATFORM == PLATFORM_MAC || PLATFORM == PLATFORM_UNIX

    #include <sys/socket.h>
    #include <net/if.h>
    #include <sys/ioctl.h>
    #include <netinet/if_ether.h>
    #include <errno.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <pthread.h>

    typedef int SOCKET;
    typedef struct sockaddr_in SOCKADDR_IN;
    typedef struct sockaddr SOCKADDR;
    typedef struct hostent HOSTENT;
    typedef unsigned char BYTE;
    typedef char TCHAR;
    #define _T(a) a
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define _tcscmp strcmp
    #define ioctlsocket fcntl
    #define _tfopen_s fopen_s
    #define _tprintf printf
    #define waitThread(tid) pthread_join(tid, NULL)
    #define THREADPROC void *
    int _getch();
    #define closesocket(s) shutdown(s, 2)
#endif

pthread_t createThread(void * (* proc)(void *), void * arg);
