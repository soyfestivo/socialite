#include "web.h"
#include "web/client.h"

using std::string;
using std::map;
using std::function;

namespace Socialite {
	namespace Web {
		string Get(string url) {
			Socialite::Web::Client client(url);
			client.connect();

			return client.getBody();
		}

		void Get(string url, std::function<void (int status, std::map<string, string>& headers, string body)> callback) {
			Socialite::Web::Client client(url);
			client.connect();

			callback(client.getStatus(), client.getHeaders(), client.getBody());
		}

		void Get(string url, std::function<void (std::map<string, string>& headers, string body)> callback) {
			Socialite::Web::Client client(url);
			client.connect();

			callback(client.getHeaders(), client.getBody());
		}

		void Get(string url, function<void (int status, string body)> callback) {
			Socialite::Web::Client client(url);
			client.connect();

			callback(client.getStatus(), client.getBody());
		}

		void Get(string url, function<void (string body)> callback) {
			Socialite::Web::Client client(url);
			client.connect();

			callback(client.getBody());
		}

		//////////////////// POST /////////////////////
		string Post(string url, string data) {
			Socialite::Web::Client client(POST, url, data);
			client.connect();

			return client.getBody();
		}

		void Post(string url, string data, std::function<void (int status, std::map<string, string>& headers, string body)> callback) {
			Socialite::Web::Client client(POST, url, data);
			client.connect();

			callback(client.getStatus(), client.getHeaders(), client.getBody());
		}

		void Post(string url, string data, std::function<void (std::map<string, string>& headers, string body)> callback) {
			Socialite::Web::Client client(POST, url, data);
			client.connect();

			callback(client.getHeaders(), client.getBody());
		}

		void Post(string url, string data, function<void (int status, string body)> callback) {
			Socialite::Web::Client client(POST, url, data);
			client.connect();

			callback(client.getStatus(), client.getBody());
		}

		void Post(string url, string data, function<void (string body)> callback) {
			Socialite::Web::Client client(POST, url, data);
			client.connect();

			callback(client.getBody());
		}
	}
}