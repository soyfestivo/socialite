FLAGS = -std=c++11 -O2
LIBS = -lssl -lcrypto -lresolv

# namespaces
web.o:
	g++ -fpic $(FLAGS) -c lib/web.cpp -o web.o

# classes
net_stream.o:
	g++ -fpic $(FLAGS) -c lib/net_stream.cpp -o net_stream.o

client.o: 
	g++ -fpic $(FLAGS) -c lib/client.cpp -o client.o

web_client.o:
	g++ -fpic $(FLAGS) -c lib/web/client.cpp -o web_client.o

all: net_stream.o client.o web_client.o web.o
	g++ -shared $(LIBS) $(FLAGS) -o libSocialte.so net_stream.o client.o web_client.o web.o

examples: all examples/example_1.cpp
	g++ -I. -L. $(FLAGS) $(LIBS) -lSocialte examples/example_1.cpp -o example_1

clean:
	-rm *.o
	-rm *.so
	-rm example_1
