/*
 * HassCrypto.cpp
 *
 *  Created on: Dec 2, 2018
 *      Author: johan
 */

#include "HassCrypto.h"
#include <iostream> // cout
#include <unistd.h> // read
#include <sys/types.h> // socket
#include <sys/socket.h> // socket
#include <netinet/in.h> // socket
#include <netdb.h>

#include <string.h> // memcpy
#include <stdio.h> // memcpy
#include <assert.h>     /* assert */

#include <stdio.h>

constexpr char SERVERADDRESS[] = "192.168.0.100";

HassCrypto::HassCrypto(int fd, bool server) :
socketFd(fd),server(server){
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		exit(1);
	}

    if(server){
		serverSetup();
	}else{
		clientSetup();
	}

	// Threads needs to be started.
	setupKeyExchange(); // Key exhange is done and a message is successfully sent.
}

void HassCrypto::serverSetup(){

}

void HassCrypto::clientSetup() {

    {
        int portno = 9000;
        struct sockaddr_in serv_addr;
        struct hostent *server;

        socketFd = socket(AF_INET, SOCK_STREAM, 0);
        if (socketFd < 0) {
            perror("ERROR opening socket");
            exit(1);
        }
        server = gethostbyname(SERVERADDRESS);
        if (server == NULL) {
            fprintf(stderr, "ERROR, no such host\n");
            exit(0);
        }
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *) server->h_addr,
              (char *) &serv_addr.sin_addr.s_addr,
              server->h_length);
        serv_addr.sin_port = htons(portno);
        if (connect(socketFd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
            perror("ERROR connecting");
            exit(1);
        }
        std::cout << "client starting" << std::endl;
    }

    /*
    int portno2 = 9002;
    struct sockaddr_in serv_addr2;
    struct hostent *server2;
    socketFd2 = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd2 < 0){
        perror("ERROR opening socket");
        exit(1);
    }
    server2 = gethostbyname(SERVERADDRESS);
    if (server2 == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr2, sizeof(serv_addr2));
    serv_addr2.sin_family = AF_INET;
    bcopy((char *)server2->h_addr,
          (char *)&serv_addr2.sin_addr.s_addr,
          server2->h_length);
    serv_addr2.sin_port = htons(portno2);
    if (connect(socketFd2,(struct sockaddr *) &serv_addr2,sizeof(serv_addr2)) < 0){
        perror("ERROR connecting");
        exit(1);
    }

    std::string msg = "starting up.\n";
    write(socketFd2, msg.c_str(), msg.length());
    std::cout << "client starting" << std::endl;
     */
}

void HassCrypto::setupKeyExchange(){
	crypto_box_keypair(publickey, secretkey);
	int n;
	CryptoMessage cMsg;
	unsigned char msg[] = "deadbeef";
	int msgLen = sizeof(msg) / sizeof(unsigned char);

	if(server){
		n = read(socketFd,otherPartPublickey,crypto_box_PUBLICKEYBYTES);
		assert(n == crypto_box_PUBLICKEYBYTES);
		n = write(socketFd, publickey, crypto_box_PUBLICKEYBYTES);
		assert(n == crypto_box_PUBLICKEYBYTES);

		// This shall have a timeout...
		readMsg(cMsg);
		assert(memcmp(&msg,cMsg.unencryptedMsg.get(), msgLen) == 0);


	}else{
        n = write(socketFd, publickey, crypto_box_PUBLICKEYBYTES);
        assert(n == crypto_box_PUBLICKEYBYTES);
	    n = read(socketFd, otherPartPublickey,crypto_box_PUBLICKEYBYTES);
        assert(n == crypto_box_PUBLICKEYBYTES);
		cMsg.unencryptedLen = msgLen;
		cMsg.unencryptedMsg.reset(new unsigned char[msgLen]);
		memcpy(cMsg.unencryptedMsg.get(), msg, msgLen);
		writeMsg(cMsg);
	}
}

void HassCrypto::writeMsg(CryptoMessage& msg){
	if(msg.encryptedLen > 0 || msg.encryptedMsg != nullptr){
		perror("Already encrypted.");
		return;
	}
	if(msg.unencryptedLen == 0 || msg.unencryptedMsg == nullptr){
		perror("No message to encrypt.");
		return;
	}

    unsigned char nonceLen[crypto_box_NONCEBYTES];
    unsigned char nonceMsg[crypto_box_NONCEBYTES];

    // create a nonce for len and msg
    randombytes_buf(nonceLen, sizeof nonceLen);
    randombytes_buf(nonceMsg, sizeof nonceMsg);

    const void* tmpVoid = &msg.unencryptedLen;
    const unsigned char* tmpChar = (const unsigned char*)tmpVoid;

	int CIPHERTEXTLEN_LEN = crypto_box_MACBYTES + sizeof(uint16_t);
    unsigned char ciphertextLen[CIPHERTEXTLEN_LEN];

    if (crypto_box_easy(ciphertextLen, tmpChar, sizeof(uint16_t), nonceLen,
    		otherPartPublickey, secretkey) != 0) {
        /* error */
    	perror("Could not encrypt the ciphertextLen");
    	exit(1);
    }

	int CIPHERTEXTMSG_LEN = crypto_box_MACBYTES + msg.unencryptedLen;
    unsigned char ciphertextMsg[CIPHERTEXTMSG_LEN];

    if (crypto_box_easy(ciphertextMsg, msg.unencryptedMsg.get(), msg.unencryptedLen, nonceMsg,
    		otherPartPublickey, secretkey) != 0) {
        /* error */
    	perror("Could not encrypt the ciphertextMsg");
    	exit(1);
    }

    unsigned int msgLen = CIPHERTEXTLEN_LEN+CIPHERTEXTMSG_LEN+2*crypto_box_NONCEBYTES;
	msg.encryptedMsg.reset(new unsigned char[msgLen]);

    unsigned int position = 0;
    memcpy(&msg.encryptedMsg.get()[position], nonceLen, crypto_box_NONCEBYTES);
    position += crypto_box_NONCEBYTES;
    memcpy(&msg.encryptedMsg.get()[position], ciphertextLen, CIPHERTEXTLEN_LEN);
    position += CIPHERTEXTLEN_LEN;
    memcpy(&msg.encryptedMsg.get()[position], nonceMsg, crypto_box_NONCEBYTES);
    position += crypto_box_NONCEBYTES;
    memcpy(&msg.encryptedMsg.get()[position], ciphertextMsg, CIPHERTEXTMSG_LEN);
    msg.encryptedLen = msgLen;

//    std::cout << "nonceLen: ";
//    for(unsigned int i = 0 ; i < crypto_box_NONCEBYTES; ++i){
//    	std::cout << std::to_string(nonceLen[i]) << " ";
//    }
//    std::cout << std::endl;
//    std::cout << "ciphertextLen: ";
//    for(int i = 0 ; i < CIPHERTEXTLEN_LEN; ++i){
//    	std::cout << std::to_string(ciphertextLen[i]) << " ";
//    }
//    std::cout << std::endl;
//    std::cout << "nonceMsg: ";
//    for(unsigned int i = 0 ; i < crypto_box_NONCEBYTES; ++i){
//    	std::cout << std::to_string(nonceMsg[i]) << " ";
//    }
//    std::cout << std::endl;
//    std::cout << "ciphertextMsg: ";
//    for(int i = 0 ; i < CIPHERTEXTMSG_LEN; ++i){
//    	std::cout << std::to_string(ciphertextMsg[i]) << " ";
//    }
//    std::cout << std::endl;
//    std::cout << "encryptedMsg: ";
//    for(unsigned int i = 0 ; i < msgLen; ++i){
//    	std::cout << std::to_string(msg.encryptedMsg.get()[i]) << " ";
//    }
//    std::cout << std::endl;

	unsigned int n;
	n = write(socketFd, msg.encryptedMsg.get(), msg.encryptedLen);
	assert(n == msg.encryptedLen);

}
void HassCrypto::readMsg(CryptoMessage& msg){
	unsigned char nonceLen[crypto_box_NONCEBYTES];
	int n;

	n = read(socketFd,nonceLen,crypto_box_NONCEBYTES);
	assert(n == crypto_box_NONCEBYTES);

//	std::cout << "nonceLen: ";
//	for(unsigned int i = 0 ; i < crypto_box_NONCEBYTES;++i){
//		std::cout << std::to_string(nonceLen[i]) << " ";
//	}
//	std::cout << std::endl;

	int CIPHERTEXTLEN_LEN = crypto_box_MACBYTES + sizeof(uint16_t);
	unsigned char ciphertextLen[CIPHERTEXTLEN_LEN];
	n = read(socketFd,ciphertextLen,CIPHERTEXTLEN_LEN);
	assert(n == CIPHERTEXTLEN_LEN);

//	std::cout << "ciphertextLen: ";
//	for( int i = 0; i < CIPHERTEXTLEN_LEN; ++i){
//		std::cout << std::to_string(ciphertextLen[i]) << " ";
//	}
//	std::cout << std::endl;

	unsigned int decryptedLen = 0;
	void* tmpVoid = &decryptedLen;
	unsigned char* tmpChar = (unsigned char*) tmpVoid;

	if (crypto_box_open_easy(tmpChar, ciphertextLen, CIPHERTEXTLEN_LEN, nonceLen,
			otherPartPublickey, secretkey) != 0) {
    	perror("Could not decrypt the ciphertextLen");
		exit(1);
	}

//	std::cout << "LENGTH: " << std::to_string(decryptedLen) << std::endl;

	unsigned char nonceMsg[crypto_box_NONCEBYTES];

	n = read(socketFd,nonceMsg,crypto_box_NONCEBYTES);
	assert(n == crypto_box_NONCEBYTES);

//	std::cout << "nonceMsg: ";
//	for(unsigned int i = 0 ; i < crypto_box_NONCEBYTES;++i){
//		std::cout << std::to_string(nonceMsg[i]) << " ";
//	}
//	std::cout << std::endl;

	int CIPHERTEXTMSG_LEN = crypto_box_MACBYTES + decryptedLen;
	unsigned char ciphertextMsg[CIPHERTEXTMSG_LEN];
	n = read(socketFd,ciphertextMsg,CIPHERTEXTMSG_LEN);
	assert(n == CIPHERTEXTMSG_LEN);

//	std::cout << "ciphertextMsg: ";
//	for( int i = 0 ; i < CIPHERTEXTMSG_LEN;++i){
//		std::cout << std::to_string(ciphertextMsg[i]) << " ";
//	}
//	std::cout << std::endl;

	msg.unencryptedMsg.reset(new unsigned char[decryptedLen]);
	msg.unencryptedLen = decryptedLen;

	if (crypto_box_open_easy(msg.unencryptedMsg.get(), ciphertextMsg, CIPHERTEXTMSG_LEN, nonceMsg,
			otherPartPublickey, secretkey) != 0) {
    	perror("Could not decrypt the ciphertextMsg");
		exit(1);
	}

//	std::cout << "MESSAGE: ";
//	for(unsigned int i = 0; i < decryptedLen; ++i){
//		std::cout << msg.unencryptedMsg.get()[i];
//
//	}
//	std::cout << std::endl;
}


HassCrypto::~HassCrypto() {
	shutdown(socketFd, 2);
	close(socketFd);
}

