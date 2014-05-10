# Hemorrhage

CC=clang
CXX=clang++
CFLAGS=-g -Wall -Werror -fvisibility=hidden -O3
CXXFLAGS=$(CFLAGS) -fvisibility-inlines-hidden -stdlib=libc++ -std=c++11
DEBUGFLAGS=-DBOOST_ASIO_ENABLE_HANDLER_TRACKING

BOOSTDIR=/opt/boost/libc++
OPENSSLDIR=/opt/apps

INCLUDES=-I$(BOOSTDIR)/include -I$(OPENSSLDIR)/include

LIBS=-L$(OPENSSLDIR)/lib -lcrypto -lssl -L$(BOOSTDIR)/lib -lboost_system

CUSTOM_SRC=\
  heartbeat.c

OBJECTS=$(subst .c,.o,$(CUSTOM_SRC))

ASIO_SRC=\
  main_asio.cc \
  Plasma.cc

SRC=\
  main.cc \
  Plasma.cc

all: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o hemorrhage $(OBJECTS) $(INCLUDES) $(LIBS) $(SRC)

asio: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -DBOOST_ASIO_SEPARATE_COMPILATION -o hemorrhage $(OBJECTS) $(INCLUDES) $(LIBS) $(ASIO_SRC)

asio-debug: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(DEBUGFLAGS) -DBOOST_ASIO_SEPARATE_COMPILATION -o hemorrhage $(OBJECTS) $(INCLUDES) $(LIBS) $(ASIO_SRC)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o hemorrhage
