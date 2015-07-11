TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt


gcc: QMAKE_CXXFLAGS += -std=c++11
unix: QMAKE_CXXFLAGS += -lpthread
unix: QMAKE_LFLAGS = -pthread

win32 {
    LIBS += -lws2_32
    LIBS += -lwsock32
}

SOURCES += ../main.cpp \
    ../structs.cpp \
    ../platform.cpp

HEADERS += \
    ../main.h \
    ../platform.h \
    ../structs.h
