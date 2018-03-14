FLAGS = -std=c++11 -O2
LIBS = -lssl -lcrypto -lresolv -lJuggler
EXTRA_INCLUDES = -I/Users/stephen/workspace/juggler -L/Users/stephen/workspace/juggler

# external libs

# namespaces
web.o:
	g++ -fpic $(FLAGS) -c lib/web.cpp -o web.o

# classes
net_stream.o:
	g++ -fpic $(FLAGS) -c lib/net_stream.cpp -o net_stream.o

client.o: 
	g++ -fpic $(FLAGS) -c lib/client.cpp -o client.o

server.o:
	g++ -fpic $(EXTRA_INCLUDES) $(FLAGS) -c lib/server.cpp -o server.o

web_client.o:
	g++ -fpic $(FLAGS) -c lib/web/client.cpp -o web_client.o

all: net_stream.o client.o web_client.o web.o server.o
	g++ -shared $(EXTRA_INCLUDES) -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib $(LIBS) $(FLAGS) -o libSocialte.so net_stream.o client.o web_client.o web.o server.o

examples: all examples/example_1.cpp examples/server.cpp
	g++ -I. -L. $(FLAGS) $(EXTRA_INCLUDES) $(LIBS) -lSocialte examples/example_1.cpp -o example_1
	g++ -I. -L. $(FLAGS) $(EXTRA_INCLUDES) $(LIBS) -lSocialte examples/server.cpp -o server

clean:
	-rm *.o
	-rm *.so
	-rm example_1
	-rm server
