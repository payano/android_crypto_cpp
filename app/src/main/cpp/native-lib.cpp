#include <jni.h>
#include <string>
#include "libsodium/include/sodium.h"
#include "HassCrypto.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_johan_cpptest_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        exit(1);
    }
    HassCrypto hcrypto(0);

    {
        CryptoMessage cMsg;
        unsigned char msg[] = "Client to Server: PLEASE RESPOND!";
        int msgLen = sizeof(msg) / sizeof(unsigned char);
        cMsg.unencryptedLen = msgLen;
        cMsg.unencryptedMsg.reset(new unsigned char[msgLen]);
        memcpy(cMsg.unencryptedMsg.get(), msg, msgLen);
        hcrypto.writeMsg(cMsg);
    }

    {
        CryptoMessage cMsg;
        hcrypto.readMsg(cMsg);
        //std::cout << "cMsg:" << cMsg.unencryptedMsg.get() << std::endl;
    }

    return env->NewStringUTF(hello.c_str());
}
