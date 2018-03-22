#ifndef _SERVER_H_
#define _SERVER_H_

#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <openssl/ssl.h>
#include <juggler>

#include "net_stream.h"

#define S_DEFAULT 0
#define S_SSL_SERVER 1

#define S_KEEP_ALIVE 2
#define S_ONE_THREAD_ONLY 4

namespace Socialite {
	void server_connection_thread(void* data);
	void server_listening_thread_run(void* data);

	class Server {
	protected:
		Juggler::ThreadManager* threads;
		volatile int mainSock;
		int waitingCount;
		int port;
		int mainLoopThreadId;
		volatile bool running;
		bool setupError;
		bool threadPerConnection;

		// SSL stuff
		bool runningSSL;
		SSL_METHOD* method;
		SSL_CTX* ctx;
		FILE* opensslErrorLogFile;
		std::string certPassword;

		bool setupSSL(std::string cert, std::string key, std::string password);
		bool setupServer(int config);
		void stop();

		// needs to be overwritten
		virtual void handleConnection(Socialite::NetStream* stream);

	public:
		Server(int portNumber, int maxThreads, int flags);
		Server(int portNumber, std::string cert, std::string key, std::string certPassword, int maxThreads, int flags);
		~Server();

		void setCertPassword();
		
		void run();

		static int pem_passwd_cb(char *buf, int size, int rwflag, void *password);
		friend void Socialite::server_connection_thread(void* data);
		friend void Socialite::server_listening_thread_run(void* data);
	};
}

#endif