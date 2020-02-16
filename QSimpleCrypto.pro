QT -= gui

TEMPLATE = lib

CONFIG += c++17
CONFIG += staticlib

HEADERS += \
    include/QAead.h \
    include/QBlockCipher.h \
    include/QCryptoError.h \
    include/QRsa.h \
    include/QSimpleCrypto_global.h \
    include/QX509.h \
    include/QX509Store.h

SOURCES += \
    sources/QAead.cpp \
    sources/QBlockCipher.cpp \
    sources/QCryptoError.cpp \
    sources/QRsa.cpp \
    sources/QX509.cpp \
    sources/QX509Store.cpp

# Default rules for deployment.
unix {
    targ