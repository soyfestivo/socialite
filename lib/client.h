#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>

#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include "net_stream.h"

#define DEFAULT 0
#define SSL_SERVER 1

namespace Socialite {
	class Client {
	private:
		int sock;
		int port;
		struct hostent* host;
		struct sockaddr_in addr;
		Socialite::NetStream* stream;
		std::string interface;

		// SSL stuff
		bool runningSSL;
		SSL_METHOD* method;
		SSL_CTX* ctx;

		bool setupSSL();
		bool setup(std::string hostname);
		std::string resolveMX(std::string name);

	public:
		Client(std::string host, int port, int config);
		~Client();
		Socialite::NetStream* connect();
		bool upgrade();
		static int pem_passwd_cb(char *buf, int size, int rwflag, void *password);
		void close();

	};
}

#endif