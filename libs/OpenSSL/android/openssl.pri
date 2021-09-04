!contains(QT.network_private.enabled_features, openssl-linked) {
    CONFIG(release, debug|release): SSL_PATH = $$PWD
                            else: SSL_PATH = $$PWD/no-asm

    equals(ANDROID_TARGET_ARCH, armeabi-v7a) {
        ANDROID_EXTRA_LIBS += \
            $$SSL_PATH/latest/arm/libcrypto_1_1.so \
            $$SSL_PATH/latest/arm/libssl_1_1.so \

            unix:!macx: LIBS += \
                -L$$PWD/latest/arm/ -lssl_1_1 \
                -L$$PWD/latest/arm/ -lcrypto_1_1 \

