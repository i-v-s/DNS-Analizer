TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
#CONFIG += c++11
QMAKE_CXXFLAGS += -std=c++11
QMAKE_CXXFLAGS += -lpthread
QMAKE_LFLAGS = -pthread

SOURCES += main.cpp \
    structs.cpp \
    platform.cpp

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    main.h \
    platform.h \
    structs.h

