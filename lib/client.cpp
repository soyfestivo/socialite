#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include <openssl/ssl.h>

#include "client.h"

#define SMTP_PORT 25
#define OUTMAIL_PORT 1000

using std::cout;
using std::string;
using Socialite::NetStream;

Socialite::Client::Client(string host, int port, int config) {
	this->port = port;
	runningSSL = false;
	stream = NULL;

	if(!setup(host)) {
		std::cout << "ERROR: Socialite::Client::Client " + host + "\n";
	}

	if(config == SSL_SERVER) {
		runningSSL = true;
		if(!setupSSL()) {
			printf("ERROR: setupSSL\n");
		}
	}
}

bool Socialite::Client::upgrade() {
	runningSSL = true;
	if(!setupSSL()) {
		printf("ERROR: setupSSL\n");
		runningSSL = false;
		return false;
	}
	if(stream != NULL) {
		if(!stream->upgrade(ctx)) {
			SSL_CTX_free(ctx);
			runningSSL = false;
			return false;
		}
	}
	return true;
}

Socialite::Client::~Client() {
	if(stream != NULL) {
		delete stream;
	}
	if(runningSSL && stream != NULL) {
		SSL_CTX_free(ctx);
	}
}

void Socialite::Client::close() {
	if(stream != NULL) {
		::close(sock);
	}
}

int Socialite::Client::pem_passwd_cb(char *buf, int size, int rwflag, void *password) {
	strncpy(buf, (char*) password, size);
	buf[size - 1] = '\0';
	return(strlen(buf));
}

bool Socialite::Client::setupSSL() {
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_library_init();

	method = (SSL_METHOD*) SSLv23_client_method(); // TLSv1_client_method
	ctx = SSL_CTX_new(method);

	if(!ctx) {
		return false;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	return true;
}

string Socialite::Client::resolveMX(string name) {
	int limit = 20;
	unsigned char response[NS_PACKETSZ];  /* big enough, right? */
	ns_msg handle;
	ns_rr rr;
	int mx_index, ns_index, len;
	char dispbuf[4096];

	if((len = res_search(name.c_str(), ns_c_in, ns_t_mx, response, sizeof(response))) < 0) {
		return "";
	}

	if(ns_initparse(response, len, &handle) < 0) {
		return "";
	}

	len = ns_msg_count(handle, ns_s_an);
	if(len < 0)
		return "";

	for(mx_index = 0, ns_index = 0;
			mx_index < limit && ns_index < len;
			ns_index++) {
		if(ns_parserr(&handle, ns_s_an, ns_index, &rr)) {
			/* WARN: ns_parserr failed */
			continue;
		}
		ns_sprintrr (&handle, &rr, NULL, NULL, dispbuf, sizeof (dispbuf));
		if(ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_mx) {
			char mxname[1024];
			dn_expand(ns_msg_base(handle), ns_msg_base(handle) + ns_msg_size(handle), ns_rr_rdata(rr) + NS_INT16SZ, mxname, sizeof(mxname));
			return string(mxname); // return first found
		}
	}

	return "";
}

bool Socialite::Client::setup(string hostname) {
	if(port == SMTP_PORT || port == OUTMAIL_PORT) {
		string mx = resolveMX(hostname);
		if(mx != "") {
			hostname = mx;
		}
	}
	//std::cout << "hostname: " << hostname << "\n";
	host = gethostbyname(hostname.c_str());
	if(host == NULL) {
		return false;
	}
	sock = socket(PF_INET /*AF_INET*/, SOCK_STREAM, 0);
	if(sock < 0) {
		return false;
	}

	// bind to a specific interface
	/*if(interface != "any") {
		int done = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE IP_RECVIF, (char*) interface.c_str(), interface.length());
		if(!done) {
			std::cout << "ERROR: cannot bind to " << interface << "\n";
		}
	}*/

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	return true;
}

NetStream* Socialite::Client::connect() {
	if(::connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == 0) {
		if(runningSSL) {
			stream = new NetStream(ctx, sock, NS_CLIENT);
		}
		else {
			stream = new NetStream(sock);
		}
		return stream;
	}
	return NULL;
}