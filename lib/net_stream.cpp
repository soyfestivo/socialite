#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cerrno>

#include <openssl/ssl.h>
#include "net_stream.h"

#define READ_SOCK(size, buff) (ssl == NULL ? recv(sock, buff, size, 0) : SSL_read(ssl, buff, size))

using std::cout;
using std::string;

Socialite::NetStream::NetStream(int s) {
	timeout = 30; // 30 seconds default timeout on read
	sock = s;
	ssl = NULL;
	isClosed = false;
	offsetA = 0;
	offsetB = 0;
}

Socialite::NetStream::NetStream(SSL_CTX* ctx, int s, int config) {
	timeout = 30; // 30 seconds default timeout on read
	ssl = SSL_new(ctx);
	sock = s;
	SSL_set_fd(ssl, sock);
	SSL_set_accept_state(ssl);
	if(config == NS_SERVER) {
		SSL_set_accept_state(ssl);
		int ret;
		if((ret = SSL_accept(ssl)) != 1) {
			cout << "SSL_accept failed: " << ret << "," << SSL_get_error(ssl, ret) << "\n";
			printError(ret);
			close();
			return;
		}
	}
	else if(config == NS_CLIENT) {
		SSL_set_connect_state(ssl);
		int ret;
		if((ret = SSL_connect(ssl)) != 1) {
			cout << "SSL_connect failed: " << ret << " " << SSL_get_error(ssl, ret) << "\n";
			printError(ret);
			close();
			return;
		}
		// client initiates the handshake
		// will save time on first SSL_read
		SSL_do_handshake(ssl);
	}
	isClosed = false;
	offsetA = 0;
	offsetB = 0;
}

bool Socialite::NetStream::isDead() {
	return isClosed;
}

int Socialite::NetStream::errorCheck() {
	int error = 0;
	socklen_t len = sizeof(error);
	int retval = getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
	if(error != 0 || retval != 0) {
		return 1;
	}
	return 0;
}

int Socialite::NetStream::getFD() {
	return sock;
}

bool Socialite::NetStream::upgrade(SSL_CTX* ctx) {
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	SSL_set_accept_state(ssl);

	SSL_set_connect_state(ssl);
	if(SSL_connect(ssl) != 1) {
		cout << "SSL_connect failed\n";
		SSL_free(ssl);
		ssl = NULL;
		return false;
	}
	// client initiates the handshake
	// will save time on first SSL_read
	SSL_do_handshake(ssl);
	return true;
}

string Socialite::NetStream::getIP() {
	if(isClosed) {
		return "0.0.0.0";
	}

	struct sockaddr addr;
	socklen_t addr_size = sizeof(struct sockaddr);
	if(errorCheck()) {
		return "";
	}
	int res = getpeername(sock, (struct sockaddr*) &addr, &addr_size);
	char ipstr[64];
	int port;

	if (addr.sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
	}
	else if(addr.sa_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
	}

	return string(ipstr); //inet_ntoa(addr.sin6_addr)
}
void Socialite::NetStream::close() {
	if(!isClosed) {
		isClosed = true;
		if(ssl != NULL) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ssl = NULL;
		}
		::close(sock);
	}
}

// similar to close but called because of an error
void Socialite::NetStream::kill() {
	try {
		close();
	}
	catch(std::exception& e) {
		cout << "exception " << e.what() << "\n";
	}
}

bool Socialite::NetStream::scanForStop(string& add) {
	char* c;
	if(offsetB < offsetA) {
		offsetA = 0;
		offsetB = 0;
		return false;
	}
	if(offsetA < 0 || offsetB < 0 || (offsetA > sizeof(buff) || offsetB > sizeof(buff))) {
		offsetA = 0;
		offsetB = 0;
		return false;
	}

	for(int i = offsetA; i < offsetB; i++) {
		c = &buff[i];
		if(*c == '\n') {
			if(i > 0 && *(c-1) == '\r') {
				add += string(&buff[offsetA], i-1 - offsetA);
			}
			else {
				add += string(&buff[offsetA], i - offsetA);
			}
			offsetA = i+1;
			return true;
		}
	}
	add += string(&buff[offsetA], offsetB - offsetA);
	offsetA = 0;
	offsetB = 0;
	return false;
}

int Socialite::NetStream::read(char* b, int n) {
	if(isClosed) {
		return -1;
	}

	int at = 0;
	if(offsetA != offsetB) { // some data remaining in buffer
		int i;
		for(i = offsetA; i < offsetB && at < n; i++) {
			b[at] = buff[i];
			at++;
		}
		if(i < offsetB) {
			offsetA = i; // we didn't need the whole buffer
			return at;
		}
	}
	// reset to show we've read everything from the buffer
	offsetA = 0;
	offsetB = 0;

	n -= at;

	fd_set readyReadFDSet, readFDSet;
	FD_ZERO(&readFDSet);
	FD_SET(sock, &readFDSet);

	int readV = 0;
	while(n > 0 && (readV = softRead(n, &b[at])) > 0) {
		at += readV;
		n -= readV;

		// DEBUGGING
		//allRead += string(b[at], read);
	}

	return at;
}

bool Socialite::NetStream::pendingRead() {
	fd_set readyReadFDSet, readFDSet;
	struct timeval returnNow;
	returnNow.tv_sec = 0;
	returnNow.tv_usec = 0;
	FD_ZERO(&readFDSet);
	FD_SET(sock, &readFDSet);

	if(offsetA != offsetB) { // we've got some data in the buffer
		return true;
	}

	readyReadFDSet = readFDSet;

	if(ssl == NULL) {
		if(select(FD_SETSIZE, &readyReadFDSet, NULL, NULL, &returnNow) < 0) { // wait on read ready
			close();
			return false;
		}

		if(FD_ISSET(sock, &readyReadFDSet)) {
			return true;
		}
	}
	else {
		return SSL_pending(ssl) > 0 ? true : false;
	}
	return false;
}

string Socialite::NetStream::read(int n) {
	char buff[n+1];
	buff[n] = '\0';
	read(buff, n);
	return string(buff, n);
}

void Socialite::NetStream::printError(int erro) {
	int err;
	if(ssl != NULL) {
		err = SSL_get_error(ssl, erro);
	}
	else {
		return;
	}
	if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		std::cout << "Socialite::NetStream::read ssl_want_read/write waiting on read...\n";
	}
	if(err == SSL_ERROR_SYSCALL) {
		std::cout << "SSL_get_error = SSL_ERROR_SYSCALL\n";
	}
	if(err == SSL_ERROR_ZERO_RETURN) {
		std::cout << "SSL_get_error = SSL_ERROR_ZERO_RETURN\n";
	}

	if(err == SSL_ERROR_WANT_CONNECT) {
		std::cout << "SSL_get_error = SSL_ERROR_WANT_CONNECT\n";
	}

	if(err == SSL_ERROR_WANT_ACCEPT) {
		std::cout << "SSL_get_error = SSL_ERROR_WANT_ACCEPT\n";
	}

	if(err == SSL_ERROR_WANT_X509_LOOKUP) {
		std::cout << "SSL_get_error = SSL_ERROR_WANT_X509_LOOKUP\n";
	}

	if(err == SSL_ERROR_SYSCALL) {
		std::cout << "SSL_get_error = SSL_ERROR_SYSCALL\n";
		std::cout << "errno: " << errno << "\n";

	}

	if(err == SSL_ERROR_SSL) {
		std::cout << "SSL_get_error = SSL_ERROR_SSL\n";
	}
}

void Socialite::NetStream::setTimeout(int minutes) {
	if(minutes >= 0) {
		timeout = minutes;
	}
}

int Socialite::NetStream::softRead(int size, char* buffPtr) {
	fd_set readyReadFDSet, readFDSet, readyExceptionSet, exceptionSet;
	FD_ZERO(&readFDSet);
	FD_ZERO(&exceptionSet);

	FD_SET(sock, &readFDSet);
	FD_SET(sock, &exceptionSet);

	struct timeval returnTimeout;
	returnTimeout.tv_sec = timeout;
	returnTimeout.tv_usec = 0;

	readyReadFDSet = readFDSet;
	readyExceptionSet = exceptionSet;
	// wait on read ready
	int readV = 0;

	// note: openSSL has it's own cache so using select is not always the best method, you can 
	// get stuck sitting longer than needed. So, you need to check pendingRead() first before defaulting back
	// to select when using SSL.
	if((ssl != NULL && pendingRead()) || select(FD_SETSIZE, &readyReadFDSet, NULL, &readyExceptionSet, timeout > 0 ? &returnTimeout : NULL) > 0) {
		if(FD_ISSET(sock, &readyReadFDSet)) { // ready to read some number of bytes
			readV = READ_SOCK(size, buffPtr);
			return readV;
		}

		if(FD_ISSET(sock, &readyExceptionSet)) { // there's a problem with the socket
			close();
			return -1;
		}
	}

	// no activity and we're past our timeout so close
	close();
	return -1;
}

string Socialite::NetStream::readLine() {
	string s;
	if(offsetA < offsetB) { // we have data to check
		if(scanForStop(s)) {
			return s;
		}
	}

	int readV = 0;
	while((readV = softRead(sizeof(buff), (char*) &buff)) > 0) {
		offsetA = 0;
		offsetB = readV < 0 ? 0 : readV;
		if(scanForStop(s)) {
			return s;
		}
	}

	if(ssl != NULL) {
		int err = SSL_get_error(ssl, readV);
		printError(err);
	}

	if(errorCheck()) {
		kill();
	}
	return s;
}

int Socialite::NetStream::write(char* data, int n) {
	int written = 0;
	int thisWrite = 0;
	int count = 0; // make sure we don't try too much

	if(isClosed) {
		return -1;
	}

	int sendSize;
	socklen_t size = sizeof(int);
	getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (void*) &sendSize, &size);

	if(ssl != NULL) {
		while(written += ((thisWrite = SSL_write(ssl, &(data[written]), n - written))) < n && thisWrite > 0 && written > -1 && count < 200) {
			if(errno != 0) { // EPIPE == broken pipe :(
				std::cout << "Socialite::NetStream::write errno\n";
				return -1;
			}
			count++;
		}
	}
	else {
		while(written += ((thisWrite = send(sock, &(data[written]), n - written, 0))) < n && thisWrite > 0 && written > -1 && count < 200) {
			if(errno != 0) { // EPIPE == broken pipe :(
				std::cout << "Socialite::NetStream::write errno\n";
				return -1;
			}
			count++;
		}
	}
	if(errorCheck()) {
		std::cout << "errorCheck returned write\n";
		kill();
		return -1;
	}
	return written;
}

int Socialite::NetStream::write(string data) {
	char* d = (char*) data.c_str();
	return write(d, strlen(d));
}

Socialite::NetStream::~NetStream() {
	close();
}
