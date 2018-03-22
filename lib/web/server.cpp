#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <regex>
#include <fstream>
#include <sstream>
#include <regex>
#include <iomanip>
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <openssl/sha.h>

#include "server.h"
#include "../util.h"

#define STDIN 0
#define STDOUT 1

using std::string;
using std::regex;
using std::smatch;
using std::cout;
using std::to_string;
using std::map;
using Socialite::Util::toHttpTimestamp;
using Socialite::Util::parseHttpTimestamp;
using Socialite::Util::sha256;
using Socialite::Util::mapPostData;

Socialite::Web::Server::Server(string cert, string key, string certPassword) : Socialite::Server(443, cert, key, certPassword, WS_MAX_CLIENT, S_SSL_SERVER) {
	cout << "New secure Web::Server starting\n";
	useSSLAlso = false;
	readConfigFile();
	sslServer = NULL; // we already are that dummy
}

Socialite::Web::Server::Server() : Socialite::Server(80, WS_MAX_CLIENT, S_DEFAULT) {
	cout << "New Web::Server starting\n";
	useSSLAlso = false;
	readConfigFile();

	// spawn a second one to handle the SSL version
	if(useSSLAlso) {
		sslServer = new Server(sslCert, sslKey, "default_password");
		sslServer->run();
	}
	else {
		sslServer = NULL;
	}
}

string Socialite::Web::Server::rewriteURL(smatch matcher, string url) {
	int n = matcher.size();
	url += "---";
	std::vector<string> args;
	for(int i = 0; i < n; i++) {
		args.push_back(string(matcher[i]));
	}
	int replaced = 0;
	for(int i = 0; i < n; i++) {
		size_t found = 0;
		string keyString = string("$") + std::to_string(i);
		//std::cout << url.length() << " > " << (found + keyString.length()) << "\n";
		std::cout << args[i] << "\n";
		string rep = string(args[i]);
		//std::cout << "rep " << rep << "\n";
		try {
			while((found = url.find("$" + std::to_string(i), found + keyString.length())) != string::npos) {
				// insert inplace
				url = url.substr(0, found) + rep + url.substr(found + keyString.length());
				// overwrite length for next interation
				if(keyString != rep) {
					keyString = rep;
				}
				replaced++;
				//std::cout << "   " << url << "\n";
				//std::cout << "   " << keyString << " size = " << keyString.length() << ", " << found << "\n";
			}
		}
		catch(std::exception& e) {
			cout << "ERROR: " << e.what() << "\n";
		}
	}
	if(replaced <= 1) {
		url.erase(url.end() - 3, url.end());
	}
	else {
		url.erase(url.end() - 2, url.end());
	}
	std::cout << "FINAL: " << url << "\n";
	return url;
}

void Socialite::Web::Server::readConfigFile() {
	std::ifstream configFile("server.config");
	string line;

	HostConfig* host = new HostConfig; // default
	hosts.insert(std::pair<std::string, HostConfig*>("AAA", host));

	smatch matcher;
	regex comment("^\\s*#.*$");
	regex hostShape("^Host ([^:]+):$");
	regex command("^(?:[\\t\\s]*)([A-Za-z]+) ([^]+)$");

	while (std::getline(configFile, line)) {
		if(regex_match(line, matcher, comment)) {
			continue;
		}
		else if(regex_match(line, matcher, hostShape)) { // new host
			regex_search(line, matcher, hostShape);
			host = new HostConfig;
			hosts.insert(std::pair<std::string, HostConfig*>(matcher[1], host));
			host->redirect = false;
			host->acceptHttp = true;
		}
		else if(regex_match(line, matcher, command)) {
			regex_search(line, matcher, command);
			if(matcher[1] == "AcceptHTTP") {
				host->acceptHttp = matcher[2] == "true" ? true : false;
			}
			else if(matcher[1] == "DocumentRoot") {
				host->docRoot = matcher[2];
			}
			else if(matcher[1] == "IndexFiles") {
				string tmp;
				std::istringstream tmpStream(matcher[2]);
				while(tmpStream >> tmp) {
					host->indexFiles.push_back(tmp);
				}
			}
			else if(matcher[1] == "Rewrite") {
				regex splitShape("^([^]+) ([^]+)$");
				smatch splitMatch;
				string a = matcher[2];

				if(regex_search(a, splitMatch, splitShape)) {
					string rule = splitMatch[1];
					string replace = splitMatch[2];
					host->rewriteRules.push_back(std::pair<string, string>(rule, replace));
					
				}
				else {
					std::cout << "Rewrite " << matcher[2] << " does not match\n";
				}
			}
			else if(matcher[1] == "NotFoundError") {
				host->notFoundPage = matcher[2];
			}
			else if(matcher[1] == "ForbiddenError") {
				host->forbiddenURI = matcher[2];
			}
			else if(matcher[1] == "ServerRewrite") {
				host->serverRewriteRules.push_back(matcher[2]);
			}
			else if(matcher[1] == "AuthRequired") {
				host->authRequired.push_back(matcher[2]);
			}
			else if(matcher[1] == "EnableSSL" && matcher[2] == "true") {
				useSSLAlso = true;
			}
			else if(matcher[1] == "SSLCertificateFile") { // global not per host
				sslCert = matcher[2];
			}
			else if(matcher[1] == "SSLCertificateKeyFile") { // global not per host
				sslKey = matcher[2];
			}
			else if(matcher[1] == "Redirect") {
				host->redirect = true;
				host->redirectHost = matcher[2];
			}
		}
	}
}

bool Socialite::Web::Server::readHeader(NetStream* ns, HttpHeader* header, int* error) {
	string lastLine = "-";
	string line = ns->readLine(); // GET line
	if(ns->isDead()) {
		*error = -1;
		return false;
	}
	header->cookies.erase(header->cookies.begin(), header->cookies.end()); // erase all cookies
	header->contentLength = 0;
	smatch matcher;
	regex shape("^([A-Z]+) ([^\\s]+) HTTP/1.*$");

	if(regex_match(line, matcher, shape)) {
		regex_search(line, matcher, shape);
		if(matcher[1] == "GET") {
			header->type = WS_GET;
		}
		else if(matcher[1] == "POST") {
			header->type = WS_POST;
		}
		else {
			header->type = -1;
		}

		header->URI = matcher[2];
	}
	else {
		cout << "Socialite::Web::Server::readHeader HEADER_BAD_REQUEST: '" << line << "'\n";
		//ns->write(HEADER_BAD_REQUEST);
		ns->close();
		*error = 400;
		return false;
	}

	// defaults
	header->ifModifiedSince = (time_t) 0;

	regex shape2("^([A-Za-z\\-]+): ([^]+)$");
	while((line = ns->readLine()) != "" && lastLine != "") {
		//cout << "Socialite::Web::Server::readHeader <<"<< line << ">>" << line.length() << ":" << (int) line[0] << "\n";
		if(line == "\r") {
			break; // ???? possibly a Chrome bug
		}
		lastLine = line;
		if(regex_match(line, matcher, shape2)) {
			regex_search(line, matcher, shape2);
			if(matcher[1] == "Connection") {
				if(matcher[2] == "keep-alive") {
					header->closeType = KEEP_ALIVE;
				}
				else if(matcher[2] == "close") {
					header->closeType = CLOSE;
				}
			}
			else if(matcher[1] == "Cookie") {
				//header->cookies = matcher[2];
				string str = matcher[2];
				smatch matcher2;
				std::regex shapeCookie("([A-Za-z0-9\\-_]+)=([^;\r\n]*)");
				while(std::regex_search(str, matcher2, shapeCookie)) {
					header->cookies.insert(std::pair<string, string>(matcher2[1], string(matcher2[2])));
					str = matcher2.suffix().str();
				}
			}
			else if(matcher[1] == "Host") {
				header->host = matcher[2];
			}
			else if(matcher[1] == "Content-Type") {
				header->contentType = matcher[2];
			}
			else if(matcher[1] == "Content-Length") {
				header->contentLength = std::stoi(matcher[2]);
			}
			else if(matcher[1] == "If-Modified-Since") {
				header->ifModifiedSince = parseHttpTimestamp(matcher[2]);
			}
		}
	}
	//std::cout << "Socialite::Web::Server::readHeader empty line: " << line.length() << ": " << line << "\n";

	if(header->type == WS_POST && header->contentLength > 0) {
		header->postData = ns->read(header->contentLength);
		std::cout << header->postData << "\n";
		mapPostData(header->postMap, header->postData);
	}
	//std::cout << "Socialite::Web::Server::readHeader done\n";
	return true;
}

string Socialite::Web::Server::cgiLaunch(string file, HttpHeader* header, string getData) {
	// int pipeFds[2];
	// if(pipe(pipeFds)) {
	// 	cout << "failed to create pipe\n";
	// 	return ""; // failed to create pipe
	// }
	// pid_t pid = fork();
	// if(pid == 0) { // child
	// 	// swap stdin and stdout for our pipe

	// 	dup2(pipeFds[0], STDIN);
	// 	close(pipeFds[0]);
	// 	dup2(pipeFds[1], STDOUT);
	// 	close(pipeFds[1]);

	// 	User* user = NULL;
	// 	string passString = "";
	// 	if(header->cookies["auth-name"] != "" && header->cookies["auth-hash"] != "" && userAccounts->verify(header->cookies["auth-name"], header->cookies["auth-hash"])) {
	// 		user = userAccounts->getUser(header->cookies["auth-name"]);
	// 		passString = string(user->username) + ":" + string(user->fName) + ":" + string(user->lName) + ":" + string(user->email);
	// 	}
	// 	if(getData == "") {
	// 		getData = "null";
	// 	}
	// 	execl("./PythonBridge", "./PythonBridge", file.c_str(), header->URI.c_str(), header->host.c_str(), getData.c_str(), passString.c_str(), NULL);

	// 	cout << "ERROR: could not launch ./PythonBridge\n";
	// 	exit(1);
	// }
	// else { // parent
	// 	string ret = "";
	// 	int c;
	// 	FILE* stream = fdopen (pipeFds[0], "r");
	// 	//cout << "getting ready to read\n";
	// 	while ((c = fgetc(stream)) != 0x0) {
	// 		ret += c;
	// 	}
	// 	fclose(stream);
	// 	// cleanup
	// 	int returnValue = waitpid(pid, NULL, 0); // blocking until it's done
	// 	close(pipeFds[0]);
	// 	close(pipeFds[1]);

	// 	return ret;
	// }
	// return "";
}

string Socialite::Web::Server::serverAPI(HttpHeader* header, HttpResponseHeader* rHeader, string ip, smatch matcher, bool* success) {
	*success = false;
	return string("override");
}

// the meat of the actual processing
void Socialite::Web::Server::handleConnection(NetStream* stream) {
	int error = 0;
	HttpHeader header;
	HttpResponseHeader rHeader;
	struct stat fileStat;
	HostConfig* currentHost;
	smatch matcher;
	int connectionUse = 0;

	stream->setTimeout(5 * 60); // die after 5 minutes of inactivity

	do { // process each request as it comes in if KEEP_ALIVE, otherwise fall through
		time_t now;
		time(&now);
		struct tm* nowTime = gmtime(&now); // shouldn't it be gmtime() who knows...
		rHeader.lastModified = mktime(nowTime); // default
		rHeader.size = -1;
		rHeader.sendContent = true;
		rHeader.isFile = false;
		rHeader.transferEncoding = "";
		rHeader.runCGI = false;
		rHeader.isForbidden = false;
		rHeader.getData = "";
		rHeader.setCookie = "";
		rHeader.relocate = false;
		rHeader.allowCache = true;

		bool serverMatched = false;
		string data;
		int fileFd = 0;
		string fullURI;
		regex getValues("^([^\\?]+)\\?([^\\?]+)$");

		readHeader(stream, &header, &error);
		if(error) {
			if(error == -1) { // broken pipe
				return;
			}
			break;
		}

		// narrow it down by host ////////////////////////
		currentHost = hosts[header.host];
		if(currentHost == NULL) {
			currentHost = hosts["AAA"]; // default
		}

		// check host parking rules /////////////////////
		if(currentHost->redirect) {
			rHeader.relocate = true;
			rHeader.URI = (port == 80 ? "http://" : "https://") + currentHost->redirectHost + header.URI;
			rHeader.sendContent = false;
			goto SEND_HEADER; // skips everything up to send header
		}
		else if(currentHost->acceptHttp == false && port == 80) { // HTTPS only
			cout << "send to secure connection\n";
			rHeader.relocate = true;
			rHeader.URI = "https://" + header.host + header.URI;
			rHeader.sendContent = false;
			goto SEND_HEADER; // skips everything up to send header
		}

		// check rewrite rules /////////////////////////////
		for(auto iter = currentHost->rewriteRules.begin(); iter != currentHost->rewriteRules.end(); ++iter) {
			regex testRegex(iter->first);
			smatch testMatcher;
			if(regex_search(header.URI, testMatcher, testRegex)) {
				header.URI = "/" + rewriteURL(testMatcher, iter->second);
			}
		}

		// strip off get values if any /////////////////////
		if(regex_search(header.URI, matcher, getValues)) {
			rHeader.getData = matcher[2];
			header.URI = matcher[1];
			cout << "GET DATA: " << matcher[2] << "\n";
		}
		//rHeader.relocate = false;
		rHeader.URI = header.URI;

		// check if auth is required //////////////////////////
		for(auto iter = currentHost->authRequired.begin(); iter != currentHost->authRequired.end(); ++iter) {
			smatch matcher2;
			if(regex_match(header.URI, matcher2, regex(*iter))) { // we've got one!
				string aName = header.cookies["auth-name"];
				string aHash = header.cookies["auth-hash"];
				cout << "  auth required for " << rHeader.URI << ": " << header.cookies["auth-name"] << " : " << header.cookies["auth-hash"] << "\n";
				if(!verifyUser(aName, aHash)) { // need to redirect
					cout << "  failed vefication\n";
					rHeader.status = HEADER_FORBIDDEN;
					rHeader.isForbidden = true;
					rHeader.URI = currentHost->forbiddenURI;
					break;
				}
			}
		}

		// check filesystem ////////////////////////
		fullURI = currentHost->docRoot + rHeader.URI;
		cout << "  deciding on: " << fullURI << "\n";  
		fileFd = open((char*) fullURI.c_str(), O_RDONLY);
		//cout << "open: " << fileFd << "\n";
		if(fileFd < 0) { // 404 ////////////////////////
			cout << "     not found " << fullURI << "\n";
			rHeader.status = HEADER_NOT_FOUND;
			rHeader.notFound = true;
			rHeader.size = 0;
			rHeader.isFile = false;
			rHeader.sendContent = true;
		}
		else { // file found ////////////////////////
			cout << "     found file " << fullURI << "\n";
			rHeader.status = HEADER_OK;
    		fstat(fileFd, &fileStat);
    		rHeader.notFound = false;
    		if(S_ISDIR(fileStat.st_mode)) { // is a directory, look for index files
    			cout << "     isDIR " << fullURI << "\n";
    			close(fileFd);
    			rHeader.notFound = true;
    			bool found = false;
    			for(auto iter = currentHost->indexFiles.begin(); iter != currentHost->indexFiles.end(); ++iter) {
    				string nowFullURI = fullURI + *iter;
    				fileFd = open((char*) nowFullURI.c_str(), O_RDONLY);
    				if(fileFd > 0) {
    					fullURI = nowFullURI;
    					fstat(fileFd, &fileStat);
    					found = true;
    					rHeader.sendContent = true;
    					rHeader.isFile = true;
    					rHeader.notFound = false;
    					break;
    				}
    			}
    			if(!found) {
    				rHeader.status = HEADER_NOT_FOUND;
    				fileFd = open((char*) fullURI.c_str(), O_RDONLY);
    			}
    		}
    		else { // normal file
    			rHeader.isFile = true;
    			rHeader.sendContent = true;
    		}
    		rHeader.size = fileStat.st_size;
    		//rHeader.transferEncoding = "chunked";
    		struct tm* modifyTime = localtime(&fileStat.st_mtime);
			rHeader.lastModified = mktime(modifyTime);
		}
		if(rHeader.notFound) {
			rHeader.status = HEADER_NOT_FOUND;
			fullURI = currentHost->docRoot + currentHost->notFoundPage;
			//rHeader.size = MESSAGE_404.length();
			rHeader.sendContent = true;
		}

		if(rHeader.lastModified - header.ifModifiedSince <= 0) {
			rHeader.status = HEADER_NOT_MODIFIED;
			rHeader.size = 0;
			rHeader.sendContent = false;
		}

		// server API checks
		serverMatched = false;
		for(auto iter = currentHost->serverRewriteRules.begin(); iter != currentHost->serverRewriteRules.end(); ++iter) {
			regex apiShape(*iter);
			if(regex_match(rHeader.URI, matcher, apiShape)) {
				cout << "     serverAPI " << rHeader.URI << "\n";
				regex_search(rHeader.URI, matcher, apiShape);
				bool apiAccepted = false;
				string ip = stream->getIP();
				cout << "     IP: " << ip << "\n";
				data = serverAPI(&header, &rHeader, ip, matcher, &apiAccepted);
				if(!apiAccepted) {
					break; // okay, let's try something else
				}
				rHeader.runCGI = true; // using the same as CGI to cutdown on the same variable
				rHeader.size = data.length();
				rHeader.status = HEADER_OK;
				time(&now);
				nowTime = localtime(&now);
				rHeader.lastModified = mktime(nowTime); // brandnew
				serverMatched = true;
				rHeader.allowCache = false; // don't cache API calls
				break;
			}
		}
		if(!serverMatched) {
			// cgi scripts check /////////
			regex shape(".*\\.py");

			if(regex_match(fullURI, matcher, shape)) {
				cout << "     cgiLaunch " << fullURI << "\n";
				rHeader.sendContent = true;
				data = cgiLaunch(fullURI, &header, rHeader.getData);
				rHeader.runCGI = true;
				rHeader.size = data.length();
				if(rHeader.status != HEADER_NOT_FOUND) { // if it wasn't found before this is an error message
					rHeader.status = HEADER_OK;
				}
				time(&now);
				nowTime = localtime(&now);
				rHeader.lastModified = mktime(nowTime); // brandnew
			}
		}

		if(rHeader.isForbidden) {
			rHeader.status = HEADER_FORBIDDEN;
		}

		SEND_HEADER:
		// send header ///////////////////////////////////////////////////////////////
		if(rHeader.relocate == true) {
			rHeader.status = HEADER_REDIRECT;
		}
		string prepHeader = rHeader.status;
		prepHeader += "Server: Socialite\r\n";

		// security stuff
		prepHeader += "X-Frame-Options: SAMEORIGIN\r\n";
		prepHeader += "X-XSS-Protection: 1; mode=block\r\n";

		if(port == 443) {
			// say all request must be made over HTTPS for the next year
			prepHeader += "Strict-Transport-Security: max-age=31536000\r\n";
		}

		if(rHeader.allowCache == false) {
			prepHeader += "Cache-Control: no-cache\r\n";
		}

		if(rHeader.relocate) { // need them to move
			prepHeader += "Location: " + rHeader.URI + "\r\n";
		}
		prepHeader += "Last-Modified: " + toHttpTimestamp(rHeader.lastModified) + "\r\n";

		if(rHeader.setCookie != "") {
			prepHeader += rHeader.setCookie;
		}

		time(&now);
		nowTime = localtime(&now);
		prepHeader += "Date: " +  toHttpTimestamp(mktime(nowTime)) + "\r\n";

		prepHeader += getContentType(fullURI);

		if(rHeader.size != -1) { // send Content-Length
			//cout << "include Content-Length\n";
			prepHeader += "Content-Length: " + to_string(rHeader.size) + "\r\n";
		}
		else {
			prepHeader += "Content-Length: 0\r\n";
		}

		/* // debugging SSL
		if(port == 80) {
			if(header.type == GET && header.closeType == KEEP_ALIVE) {
				prepHeader += "Connection: keep-alive\r\n";
			}
			else { // close after a post
				prepHeader += "Connection: close\r\n";
			}
		}
		else { // SSL don't use keep-alive?
			prepHeader += "Connection: close\r\n";
		}*/

		if(header.type == WS_GET && header.closeType == KEEP_ALIVE) {
			prepHeader += "Keep-Alive: timeout=5, max=100\r\n";
			prepHeader += "Connection: keep-alive\r\n";
		}
		else { // close after a post
			prepHeader += "Connection: close\r\n";
		}

		prepHeader += "\r\n";
		stream->write(prepHeader); // the header is done, send it now

		// send content ////////////////////////////////////////////////////////////
		if(rHeader.runCGI) {
			stream->write(data); // data from CGI return
			close(fileFd);
		}
		else if(rHeader.sendContent) {
			if(rHeader.isFile && !rHeader.notFound) {
				cout << "      read file: " << fullURI << "\n";
				int readVal = 0;
				char buffer[4096];
				while((readVal = read(fileFd, buffer, 4096)) != 0) {
					if(rHeader.size != -1) { // we are using Content-Length
						//cout << "sending content\n";
						stream->write(buffer, readVal);
					}
				}
				close(fileFd);
			}
			else if(rHeader.notFound) {
				stream->write(MESSAGE_404);
			}
		}
		else {
			if(rHeader.isFile) {
				close(fileFd);
			}
		}
		if(header.type == WS_POST) {
			header.closeType = CLOSE; // don't keep trying
		}
		connectionUse++;
	} while(header.closeType == KEEP_ALIVE && !stream->isDead() && connectionUse < 100);

	cout << "close connection\n";
	stream->close();
}

bool Socialite::Web::Server::verifyUser(std::string username, std::string hash) {
	// override me!
	return false;
}

const string Socialite::Web::Server::getContentType(string uri) {
	struct stat fileMeta;
	smatch matcher;
	regex shape("^.*\\.([A-Za-z0-9]+)$");
	std::string fileType;
	if(regex_match(uri, matcher, shape)) {
		regex_search(uri, matcher, shape);
		fileType = matcher[1];
	}
	else {
		return CONTENT_TYPE_HTML;
	}
	if(stat(uri.c_str(), &fileMeta) != 0) {
		return CONTENT_TYPE_HTML; // this is for 404
	}
	if(fileType == "html" || fileType == "php" || fileType == "py") {
		return CONTENT_TYPE_HTML;
	}
	if(fileType == "css") {
		return CONTENT_TYPE_CSS;
	}
	if(fileType == "js") {
		return CONTENT_TYPE_JS;
	}
	if(fileType == "jpg") {
		return CONTENT_TYPE_JPG;
	}
	if(fileType == "jpeg") {
		return CONTENT_TYPE_JPEG;
	}
	if(fileType == "png") {
		return CONTENT_TYPE_PNG;
	}
	if(fileType == "gif") {
		return CONTENT_TYPE_GIF;
	}
	if(fileType == "bmp") {
		return CONTENT_TYPE_BMP;
	}
	if(fileType == "pdf") {
		return CONTENT_TYPE_PDF;
	}
	if(fileType == "exe" || fileType == "zip") {
		return CONTENT_TYPE_EXE;
	}
	if(fileType == "doc" || fileType == "docx") {
		return CONTENT_TYPE_DOC;
	}
	if(fileType == "mp3") {
		return CONTENT_TYPE_MP3;
	}
	if(fileType == "ico") {
		return CONTENT_TYPE_ICO;
	}
	if(fileType == "svg") {
		return CONTENT_TYPE_SVG;
	}
	if(fileType == "woff2") {
		return CONTENT_TYPE_WOFF2;
	}
	if(fileType == "ttf") {
		return CONTENT_TYPE_TTF;
	}
	return CONTENT_TYPE_HTML; // default
}

Socialite::Web::Server::~Server() {
	stop();
	std::cout << "Web::Server on port " << port << " shutting down\n";

	if(sslServer != NULL) {
		delete sslServer;
	}
}