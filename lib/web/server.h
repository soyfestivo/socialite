#ifndef _WEBSERVER_H_
#define _WEBSERVER_H_

#include <vector>
#include <map>
#include <regex>

#include "server.h"
#include "../server.h"

// we need a lot because stupid chrome can open up to about
// 7-8 threads just from visiting the site once. No clue why.
// usually a minimum of 4.
#define WS_MAX_CLIENT 35

#define WS_GET 0x1a1
#define WS_POST 0x1b1

#define KEEP_ALIVE 0x1c1
#define CLOSE 0x1d1

const std::string HEADER_SERVER_ERROR = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
const std::string HEADER_BAD_REQUEST = "HTTP/1.1 400 Bad Request\r\n\r\n";

const std::string HEADER_FORBIDDEN = "HTTP/1.1 403 Forbidden\r\n";
const std::string HEADER_NOT_FOUND = "HTTP/1.1 404 Not Found\r\n";
const std::string HEADER_OK = "HTTP/1.1 200 OK\r\n";
const std::string HEADER_MOVED = "HTTP/1.1 301 Permanently Moved\r\n";
const std::string HEADER_NOT_MODIFIED = "HTTP/1.1 304 Not Modified\r\n";
const std::string HEADER_REDIRECT = "HTTP/1.1 303 See Other\r\n";

const std::string CONTENT_TYPE_TEXT = "Content-type: text/plain; charset=UTF-8\r\n";
const std::string CONTENT_TYPE_HTML = "Content-type: text/html; charset=UTF-8\r\n";
const std::string CONTENT_TYPE_CSS = "Content-type: text/css; charset=UTF-8\r\n";
const std::string CONTENT_TYPE_EXE = "Content-type: application/octet-stream\r\n";
const std::string CONTENT_TYPE_DOC = "Content-type: application/msword\r\n";

const std::string CONTENT_TYPE_BMP = "Content-type: image/bmp\r\n";
const std::string CONTENT_TYPE_PNG = "Content-type: image/png\r\n";
const std::string CONTENT_TYPE_GIF = "Content-type: image/gif\r\n";
const std::string CONTENT_TYPE_JPG = "Content-type: image/jpg\r\n";
const std::string CONTENT_TYPE_JPEG = "Content-type: image/jpeg\r\n";
const std::string CONTENT_TYPE_ICO = "Content-type: image/x-icon\r\n";
const std::string CONTENT_TYPE_WOFF2 = "Content-type: font/woff2\r\n";
const std::string CONTENT_TYPE_TTF = "Content-type: font/truetype\r\n";

const std::string CONTENT_TYPE_JS = "Content-type: application/x-javascript\r\n";
const std::string CONTENT_TYPE_PDF = "Content-type: application/pdf\r\n";
const std::string CONTENT_TYPE_MP3 = "Content-type: audio/mpeg\r\n";

const std::string CONTENT_TYPE_SVG = "Content-type: image/svg+xml\r\n";


const std::string MESSAGE_404 = "<h2>404 Not Found</h2><p>This file was not found</p>";

typedef struct http_h {
	int type;                    // WS_POST / WS_GET
	int closeType;               // KEEP_ALIVE / CLOSE
	std::string URI;             // /some/folder/img.jpg
	std::string host;            // google.com
	std::map<std::string, std::string> cookies;         // 
	std::string contentType;     // type of post content
	time_t ifModifiedSince;      // get whole version otherwise return 304
	int contentLength;           // only used when POST
	std::string postData;        // if type == POST, get data from contentlength
	std::map<std::string, std::string> postMap;
} HttpHeader;

typedef struct host_config {
	bool acceptHttp;
	std::string docRoot;
	std::vector<std::string> indexFiles;
	std::string notFoundPage;
	std::vector<std::pair<std::string, std::string>> rewriteRules;
	std::vector<std::string> serverRewriteRules;
	std::vector<std::string> authRequired;
	std::string forbiddenURI;
	bool redirect;
	std::string redirectHost;
} HostConfig;

typedef struct http_r_h {
	std::string status;     //
	std::string URI;        // /some/folder/img.jpg
	bool relocate;          // they need to move somewhere else
	unsigned int size;      // content length
	bool isFile;            // read from open fd
	std::string transferEncoding;  // can be chunked for example
	time_t lastModified;    // last time this was modified
	bool sendContent;       // if false, send nothing
	bool notFound;          // was not found
	bool runCGI;            // the output is a CGI script
	std::string getData;    //
	bool isForbidden;       // this is true when they cannot access this path
	std::string setCookie;  // values added to header
	bool allowCache;        // sets cache-control: no-cache if false
} HttpResponseHeader;

namespace Socialite {
	namespace Web {
		class Server : public Socialite::Server {
		protected:
			std::string baseURI;
			std::map<std::string, HostConfig*> hosts;

			bool useSSLAlso;
			std::string sslCert;
			std::string sslKey;
			Socialite::Web::Server* sslServer;

			void handleConnection(NetStream* stream) override;

			bool readHeader(NetStream* ns, HttpHeader* header, int* error);
			void readConfigFile();
			std::string rewriteURL(std::smatch matcher, std::string url);
			std::string cgiLaunch(std::string file, HttpHeader* header, std::string getData);

			const std::string getContentType(std::string uri);
			
			// override us!
			std::string serverAPI(HttpHeader* header, HttpResponseHeader* rHeader, std::string ip, std::smatch matcher, bool* success);
			bool verifyUser(std::string username, std::string hash);
		public:
			// HTTPS init
			Server(std::string cert, std::string key, std::string certPassword);
			// HTTP init
			Server();

			~Server();
		};
	}
}

typedef struct wserver_h {
	bool* running;
	int publicFd;
	Socialite::Web::Server* server;
} WebServerInfo;

typedef struct connect_h {
	int fd;
	Socialite::NetStream* stream;
	Socialite::Web::Server* server;
} ConnectionInfo;

#endif