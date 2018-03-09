#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <regex>
#include <openssl/ssl.h>

#include "client.h"

using std::cout;
using std::string;
using std::regex_search;
using std::smatch;
using std::regex_match;
using std::regex;
using std::stoi;

void trim(string& str) {
	int t = 0;
	for(auto it = str.begin(); it != str.end(); ++it) {
		if(isspace(*it)) {
			t++;
		}
		else {
			break;
		}
	}
	str.erase(0, t);
	t = 0;

	for(auto it = str.end(); it != str.begin(); --it) {
		if(isspace(*it)) {
			t++;
		}
		else {
			break;
		}
	}
	str.erase(strlen(str.c_str()), t);
}

string Socialite::Web::Client::getHeader() {
	return rawHeader;
}

std::map<std::string, std::string>& Socialite::Web::Client::getHeaders() {
	return headers;
};

string Socialite::Web::Client::getBody() {
	return bodyContent;
}

Socialite::Web::Client::Client(string type, string url, string postContent) : Socialite::Web::Client::Client(url) { 
	connectionType = type;
	postData = postContent;
}

Socialite::Web::Client::Client(string url) {
	connectionType = GET;

	smatch matcher;
	regex urlFormatFull("^(https://|http://)([^/]*)/(.*)?$");
	regex urlFormatPart("^(https://|http://)?([^/]*)$");
	regex urlFormatPartLength("^([^]*)/(.*)$");
	contentLength = 0;
	body = NULL;
	readTillClose = false;
	this->interface = interface;

	protocol = "http://";

	if(regex_match(url, matcher, urlFormatFull)) {
		regex_search(url, matcher, urlFormatFull);
		//cout << "url matches:" << url << " (" << matcher[1] << ")" << "\n";
		protocol = matcher[1];
		uri = matcher[3];
		host = matcher[2];
		uri = "/" + uri;
	}
	else if(regex_match(url, matcher, urlFormatPart)) {
		protocol = matcher[1];
		uri = "/";
		host = matcher[2];
	}
	else if(regex_match(url, matcher, urlFormatPartLength)) {
		//protocol = matcher[1];
		uri = matcher[2];
		uri = "/" + uri;
		host = matcher[1];
	}
	else {
		cout << "ERROR: bad URL format\n";
	}
	//cout << "URI: " << uri << "\n";
}

void Socialite::Web::Client::processHeaderAttr(string line) {
	smatch matcher;

	string key;
	string value;

	regex format("^(.*): (.*)$");

	if(regex_match(line, matcher, format)) {
		regex_search(line, matcher, format);
		key = matcher[1];
		value = matcher[2];

		trim(key);
		trim(value);

		headers[key] = value;

		if(key == "Location") {
			location = value;
			return;
		}
		if(key == "Content-Length") {
			contentLength = stoi(value);
			return;
		}
		if(key == "Transfer-Encoding") {
			transferEncoding = value;
			return;
		}
		if(key == "Connection" && value == "close") {
			readTillClose = true;
			return;
		}
		if(key == "Set-Cookie") {
			//TODO
			return;	
		}
	}
}

void Socialite::Web::Client::processHeaderStatus(string line) {
	smatch matcher;
	regex format("^HTTP/1.* ([0-9]+) (.*)$");
	if(regex_match(line, matcher, format)) {
		regex_search(line, matcher, format);
		statusCode = stoi(matcher[1]);
	}
}

int Socialite::Web::Client::getStatus() {
	return statusCode;
}

string Socialite::Web::Client::readHeader() {
	string lastLine = "-";
	string line = ns->readLine(); // status line
	rawHeader = line + "\n";
	processHeaderStatus(line);

	while((line = ns->readLine()) != "" && lastLine != "") {
		rawHeader += line + "\r\n";
		lastLine = line;
		processHeaderAttr(line);
	}
	return rawHeader;
}

bool Socialite::Web::Client::connect() {
	if(protocol == "http://") {
		client = new Socialite::Client(host, 80, DEFAULT);
	}
	else {
		client = new Socialite::Client(host, 443, SSL_SERVER);
	}
	ns = client->connect();
	if(ns == NULL) {
		return false;
	}
	ns->write(connectionType + " " + uri + " HTTP/1.1\r\n");
	ns->write("Host: " + host + "\r\n");
	ns->write("Connection: close\r\n");
	if(connectionType == POST) {
		ns->write("Content-Length: " + std::to_string(postData.size()) + "\r\n");
	}
	ns->write("\r\n");
	if(connectionType == POST) {
		ns->write(postData);
	}
	readHeader();

	if(contentLength > 0) { // we have a content length sent
		body = (char*) malloc(contentLength);
		ns->read(body, contentLength);
		bodyContent = string(body, contentLength);
	}
	else if(transferEncoding == "chunked") { // read each chunk
		string chunkSizeStr;
		size_t chunkSize = 1; // dummy value for now

		while(chunkSize > 0) {
			chunkSizeStr = ns->readLine(); // should be the first chunk size
			trim(chunkSizeStr);
			chunkSize = stoi("0x" + chunkSizeStr, NULL, 16);
			if(chunkSize == 0) {
				break;
			}
			body = (char*) malloc(sizeof(char) * chunkSize);
			int index = 0;
			int remaining = chunkSize;
			while(remaining > 0) {
				int read = ns->read(&body[index], remaining);
				index += read;
				remaining -= read;
			}
			if(remaining < 0) { // we have a serious problem
				cout << "ERROR: Socialite::Web::Client::connect() remaining: " << remaining << "\n";
				cout << "chunkSize: " << chunkSize << "\n";
				cout << "index: " << index << "\n";
				return false;
			}
			string chunk(body, (size_t) chunkSize);

			bodyContent += chunk; // last \r\n

			free(body); // so we can start over
			body = NULL; // for destructor

			ns->readLine(); // clear out that last pesky \r\n
		}
	}
	else if(readTillClose) { // read until connection is closed
		body = (char*) malloc(1024);
		bodyContent = "";
		int read = 0;
		while((read = ns->read(body, 1024)) > 0) {
			bodyContent += string(&body[0], read);
		}
	}

	client->close();
	return true;
}

Socialite::Web::Client::~Client() {
	if(body != NULL) {
		free(body);
	}
	delete client;
}