/*
 * HassCrypto.h
 *
 *  Created on: Dec 2, 2018
 *      Author: johan
 */

#pragma once
#include "libsodium/include/sodium.h"
#include <memory>

struct CryptoMessage {
	std::unique_ptr<unsigned char[]> unencryptedMsg;
	unsigned int unencryptedLen = 0;
	std::unique_ptr<unsigned char[]> encryptedMsg;
	unsigned int encryptedLen = 0;
};
class HassCrypto {
private:
	unsigned char secretkey[crypto_box_SECRETKEYBYTES];
	unsigned char publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char otherPartPublickey[crypto_box_PUBLICKEYBYTES];
	int socketFd;
	bool server;

	void serverSetup();
	void clientSetup();
	void setupKeyExchange();

public:
	HassCrypto(int fd, bool server=false);
	void writeMsg(CryptoMessage& msg);
	void readMsg(CryptoMessage& msg);
	virtual ~HassCrypto();
};

