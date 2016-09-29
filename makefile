CC=g++
DEFS=-std=c++11 -fno-strict-aliasing -O3 -DNDEBUG
STDLIBS=-lboost_system -lcrypto -lssl -lcpprest -luuid

TARGET=azkvault
ROOTDIR=/home/cljung/cpp

CASABLANCA_DIR=$(ROOTDIR)/casablanca/Release
CASABLANCA_BINDIR=$(CASABLANCA_DIR)/build.release/Binaries

INC=-I$(CASABLANCA_DIR)/include -I$(AZURECPP_DIR)/includes

AZURECPP_DIR=$(ROOTDIR)/azure-storage-cpp/Microsoft.WindowsAzure.Storage
AZURECPP_BINDIR=$(AZURECPP_DIR)/build.release/Binaries

LIB1=-L$(CASABLANCA_BINDIR) -L$(AZURECPP_BINDIR)
RDYNAMIC=$(AZURECPP_BINDIR)/libazurestorage.so $(CASABLANCA_BINDIR)/libcpprest.so

all:	app

$(TARGET).o: $(TARGET).cpp 
	$(CC) $(DEFS) $(INC) $(TARGET).cpp -o $(TARGET) $(LIB1) $(STDLIBS) -rdynamic $(RDYNAMIC) -Wl,-rpath,$(AZURECPP_BINDIR):$(CASABLANCA_BINDIR)
	chmod +x $(TARGET)

app: $(TARGET).o

