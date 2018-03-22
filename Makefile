FLAGS = -std=c++11 -O2
LIBS = -lssl -lcrypto -lresolv -lJuggler
EXTRA_INCLUDES = -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

# namespaces
web.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/web.cpp -o web.o

# classes
net_stream.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/net_stream.cpp -o net_stream.o

client.o: 
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/client.cpp -o client.o

server.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/server.cpp -o server.o

web_server.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/web/server.cpp -o web_server.o

util.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/util.cpp -o util.o

web_client.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/web/client.cpp -o web_client.o

all: net_stream.o client.o web_client.o web.o server.o web_server.o util.o
	g++ -shared $(EXTRA_INCLUDES) -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib $(LIBS) $(FLAGS) -o libSocialte.so net_stream.o client.o web_client.o web.o server.o web_server.o util.o

install: all
	cp socialite /usr/local/include
	-mkdir /usr/local/include/socialite_lib
	cp -r lib/*.h /usr/local/include/socialite_lib
	-mkdir /usr/local/include/socialite_lib/web
	cp -r lib/web/*.h /usr/local/include/socialite_lib/web
	cp libSocialte.so /usr/local/lib

examples: install examples/example_1.cpp examples/server.cpp
	g++ -I. -L. $(FLAGS) $(EXTRA_INCLUDES) $(LIBS) -lSocialte examples/example_1.cpp -o example_1
	g++ -I. -L. $(FLAGS) $(EXTRA_INCLUDES) $(LIBS) -lSocialte examples/server.cpp -o server
	g++ -I. -L. $(FLAGS) $(EXTRA_INCLUDES) $(LIBS) -lSocialte examples/web_server.cpp -o web_server

clean:
	-rm *.o
	-rm *.so
	-rm example_1
	-rm server
	-rm web_server
