# android_crypto_cpp
Libsodium for android, C++


This a proof of concept that an android application can use the libsodium library together with c++.

I have created a HassCrypto class that makes the secure communication easier to create.

The HassCrypto.cpp and HassCrypto.h file is currently beeing developed in my other repository: hass_server.


To build the libsodium library for Android, download the library package.

Unpack the library.

cd into the library.

$ ANDROID_NDK_HOME=~/Android/Sdk/ndk-bundle ./dist-build/android-armv8-a.sh

The line above will compile the libsodium library for armv8 chipset (that's my CPU type)

