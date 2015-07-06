#include "platform.h"
#include <stdio.h>

#if PLATFORM == PLATFORM_MAC || PLATFORM == PLATFORM_UNIX

#include <termios.h>


int _getch( )
{
    struct termios oldt,
    newt;
    int ch;
    tcgetattr( STDIN_FILENO, &oldt );
    newt = oldt;
    newt.c_lflag &= ~( ICANON | ECHO );
    tcsetattr( STDIN_FILENO, TCSANOW, &newt );
    ch = getchar();
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
    return ch;
}

pthread_t createThread(void * (* proc)(void *), void * arg)
{
    pthread_t r;
    if(int e = pthread_create(&r, NULL, proc, arg))
    {
        printf("Unable to create thread(error %d)", e);
        return 0;
    }
    return r;
}


#elif PLATFORM == PLATFORM_WINDOWS

HANDLE createThread(void * (* proc)(void *), void * arg)
{
    return CreateThread(0, 0, test ? testThread : recvThread, (void *)verb, 0, 0);
}


#endif
