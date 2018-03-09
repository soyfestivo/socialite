#ifndef _WEBCLIENT_H_
#define _WEBCLIENT_H_

#include <cstring>
#include <map>

#include "../net_stream.h"
#include "../client.h"

#define GET "GET"
#define POST "POST"

namespace Socialite {
	namespace Web {
		class Client {
		private:
			std::string connectionType; // GET or POST
			std::string postData;

			Socialite::Client* client;
			std::string protocol;
			std::string uri;
			std::string host;
			Socialite::NetStream* ns;
			std::string interface;

			// response header
			std::map<std::string, std::string> headers;

			std::string rawHeader;
			int statusCode;
			std::string location;
			int contentLength;
			std::string transferEncoding;
			bool readTillClose;

			//body
			char* body;
			std::string bodyContent;

			std::string readHeader();
			void processHeaderAttr(std::string line);
			void processHeaderStatus(std::string line);

		public:
			Client(std::string url);
			Client(std::string type, std::string url, std::string postData);
			
			bool connect();
			int getStatus();
			std::map<std::string, std::string>& getHeaders();
			std::string getHeader();
			std::string getBody();
			~Client();	
		};
	}
}

#endif