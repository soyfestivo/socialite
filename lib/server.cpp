#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <regex>
#include <fstream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server.h"

using std::cout;
using std::string;
using std::regex;
using std::smatch;
using std::stoi;
using Socialite::NetStream;

struct connection_thread_h {
	Socialite::Server* server;
	NetStream* stream;
};

// implied SSL given cert and key file paths
Socialite::Server::Server(int portNumber, string cert, string key, string certPassword, int maxThreads, int flags) {
	threads = new Juggler::ThreadManager(maxThreads + 1); // +1 for listening thread
	mainLoopThreadId = -1;
	setupError = false;
	if(flags & S_ONE_THREAD_ONLY) {
		threadPerConnection = true;
	}
	else {
		threadPerConnection = false;
	}
	port = portNumber;
	runningSSL = true;
	waitingCount = 4;

	if(!setupSSL(cert, key, certPassword)) {
		setupError = true;
		printf("ERROR: setupSSL\n");
		//exit(1);
	}

	if(!setupServer(flags)) {
		setupError = true;
		printf("ERROR: setupServer\n");
		//exit(1);
	}
}

Socialite::Server::Server(int portNumber, int maxThreads, int flags) {
	threads = new Juggler::ThreadManager(maxThreads + 1); // +1 for listening thread
	mainLoopThreadId = -1;
	setupError = false;
	if(flags & S_ONE_THREAD_ONLY) {
		threadPerConnection = true;
	}
	else {
		threadPerConnection = false;
	}
	port = portNumber;
	runningSSL = false;
	waitingCount = 4;

	if(flags & S_SSL_SERVER) {
		runningSSL = true;
		if(!setupSSL("./cert_client.pem", "./key_client.pem", "default_password")) {
			setupError = true;
			printf("ERROR: setupSSL\n");
		}
	}
	else {
		ctx = NULL;
	}

	if(!setupServer(flags)) {
		setupError = true;
		printf("ERROR: setupServer\n");
	}
	running = false;
}

bool Socialite::Server::setupSSL(string cert, string key, string password) {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	method = (SSL_METHOD*) TLSv1_2_server_method(); // TLSv1_server_method
	ctx = SSL_CTX_new(method);

	if(!ctx) {
		return false;
	}

	SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*) password.c_str());
	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);

	if(!SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM)) {
		return false;
	}

	std::ifstream certTest(cert);
	string line;
	int certCount = 0;
	while(std::getline(certTest, line)) {
		if(line == "-----BEGIN CERTIFICATE-----") {
			certCount++;
		}
	}

	if(certCount > 1) { // we've got a chain
		if(SSL_CTX_use_certificate_chain_file(ctx, cert.c_str()) != 1) {
			return false;
		}
	}
	else {
		if(SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) != 1) {
			return false;
		}
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		return false;
	}

	return true;
}

bool Socialite::Server::setupServer(int config) {
	mainSock = socket(AF_INET, SOCK_STREAM, 0);
	if(mainSock < 0) {
		printf("ERROR: socket\n");
		return false;
	}
	int reuse_true = 1;

	// no timeout between restarting servers
	setsockopt(mainSock, SOL_SOCKET, SO_REUSEADDR, &reuse_true, sizeof(reuse_true));

	if(config & S_KEEP_ALIVE) {
		// use keep-alive to ping the connection every now and again to make sure
		// it doesn't go dead
		setsockopt(mainSock, SOL_SOCKET, SO_KEEPALIVE, &reuse_true, sizeof(reuse_true));
	}
	// this might be an OS X only thing: SO_REUSEPORT
	//setsockopt(mainSock, SOL_SOCKET, SO_REUSEPORT, &reuse_true, sizeof(reuse_true));

	struct sockaddr_in addr; // internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port); // byte order is significant
	addr.sin_addr.s_addr = INADDR_ANY; // listen to all interfaces
	//addr.sin_addr = INADDR_ANY; // listen to all interfaces

	if(bind(mainSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		printf("errno: %i\n", errno);
		if(errno == 13) {
			printf("Permission Denined! Couldn't bind to %i. Are you maybe you didn't launch as root.\n", port);
		}
		printf("Setup failed\n");
		return false;
	}

	if(listen(mainSock, waitingCount) < 0) {
		printf("ERROR: listen\n");
		return false;
	}
	return true;
}

int Socialite::Server::pem_passwd_cb(char *buf, int size, int rwflag, void *password) {
	strncpy(buf, (char*) password, size);
	buf[size - 1] = '\0';
	return (strlen(buf));
}

void Socialite::Server::stop() {
	if(running) {
		running = false;
		// should unbind and then mainloop `server_listening_thread_run`
		// and will close 
		std::cout << "Socialite::Server::stop closing mainsock " << mainSock << " on port " << port << "\n";
		shutdown(mainSock, SHUT_WR);
		close(mainSock);
		if(ctx != NULL) {
			SSL_CTX_free(ctx);
		}
	}
}

void Socialite::Server::handleConnection(NetStream* stream) {
	// do stuff
	stream->write("hello!\n");
	std::cout << "should never reach this empty function!\n";
	stream->close();
}

void Socialite::server_connection_thread(void* data) {
	struct connection_thread_h* info = (struct connection_thread_h*) data;
	info->server->handleConnection(info->stream);
	if(info->stream->isDead() == false) {
		info->stream->close();
	}
	free(info);
}

void Socialite::server_listening_thread_run(void* data) {
	Socialite::Server* server = (Socialite::Server*) data;
	int sessionSock;
	struct sockaddr_in client_addr;
	unsigned int socklen = sizeof(client_addr);
	while(server->running) {
		if((sessionSock = accept(server->mainSock, (struct sockaddr*) &client_addr, &socklen)) > 0) {
			cout << "** new connection " << "\n";
			NetStream* stream;
			if(server->runningSSL) {
				stream = new NetStream(server->ctx, sessionSock, NS_SERVER);
			}
			else {
				stream = new NetStream(sessionSock);	
			}

			// spawn thread to handle connection
			if(!server->threadPerConnection) {
				struct connection_thread_h* info = (struct connection_thread_h*) malloc(sizeof(struct connection_thread_h));
				info->server = server;
				info->stream = stream;
				string des = string("server thread handling connection for ") + stream->getIP() + " on port " + std::to_string(server->port) + " fd " + std::to_string(stream->getFD());
				if(server->threads->lease(server_connection_thread, (void*) info, des) >= 0) { // returns index position
					std::cout << "server spawned new thread to handle it\n";
					continue;
				}
				else { // can't lease a new thread
					std::cout << "server out of threads\n";
					stream->write("SERVER ERROR: OUT OF THREADS");
					stream->close();
					free(info);
				}
			}
			else {
				server->handleConnection(stream);
			}
		}
		else {
			std::cout << "Server accept returned < 0\n";
		}
	}
	cout << "Server main accept loop ended, exiting\n";
	printf("stop\n");
	server->stop();
}

void Socialite::Server::run() {
	if(setupError) {
		std::cout << "ERROR Socialite::Server::run cannot run because there was a setup error\n";
		return;
	}
	running = true;
	mainLoopThreadId = threads->lease(server_listening_thread_run, (void*) this, "server accept thread listening on port " + std::to_string(port)); // spawn mainloop thread
}

Socialite::Server::~Server() {
	std::cout << "Server shutting down\n";
	stop();
	if(mainLoopThreadId != -1) {
		// wait for the main loop to close, we have to do this 
		// for fast reuse of the same port so we don't get a errno 98.
		std::cout << "waiting for main server thread to close...\n";
		threads->kill(mainLoopThreadId);
	}
	delete threads;
}