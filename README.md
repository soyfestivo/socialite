# Socialite
*For all your networking needs*

## Installation
Installation is easy! All you need to do is compile:
```bash
$ make all
```
And then add when compiling make sure to include the location of the lib with both `-I` and `-L` like so:
```bash
$ g++ -I/path/to/socialite -L/path/to/socialite -lSocialite ... my_files.cpp ... -o ...
```
### Dependencies
* OpenSSL for support of encrpyted connections (https) 
* `resolv` for DNS lookups
## Example
### Simple Web request
Making a web request and receiving the body, the status, and the headers if needed
```C++
#include <socialite>

using std::string;
using std::map;
using std::cout;

// very simple get request
cout << Socialite::Web::Get("http://google.com") << "\n";

// let's use encrypted channels ;)
cout << Socialite::Web::Get("https://google.com") << "\n";

// what if we want the status?
Socialite::Web::Get("https://www.google.com/invalid_url", [](int status, string body) -> void {
	cout << body << "\n";
	assert(status == 404);
});

// what if want to check headers?
Socialite::Web::Get("http://github.com", [](int status, map<string, string>& headers, string body) -> void {
	assert(headers["Transfer-Encoding"] == "chunked"); // GH's web servers uses the chunked encoding
});
```
### POSTs
Posting data is just as easy!
```C++
Socialite::Web::Post("http://github.com/session", "login=me&password=banana", [](int status, string body) -> void {
	assert(status == 200);
	assert(body.find("login faied") != std::string::npos);
});
```