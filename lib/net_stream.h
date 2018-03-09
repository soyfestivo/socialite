#ifndef _NETSTREAM_H_
#define _NETSTREAM_H_

#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <openssl/ssl.h>

#define NS_SERVER 0
#define NS_CLIENT 1

namespace Socialite {
	class NetStream {
	private:
		SSL* ssl;
		int sock;
		bool isClosed;
		char buff[512];
		int offsetA;
		int offsetB;
		int timeout;

		int errorCheck();
		void kill();
		void printError(int err);
		int softRead(int size, char* buffPtr);

		//std::string allRead; // DEBUGGING ONLY

	public:
		NetStream(int s);
		NetStream(SSL_CTX* ctx, int s, int config);

		void close();
		void setTimeout(int seconds);
		std::string readLine();
		int read(char* buff, int n);
		std::string read(int n);
		int write(char* data, int n);
		int write(std::string data);
		int getFD();
		bool scanForStop(std::string& add);
		std::string getIP();
		bool pendingRead();
		bool upgrade(SSL_CTX* ctx); // only for client

		bool isDead();

		~NetStream();
	};
}

#endif