.PHONY: all debug release clean

RELEASE_FLAGS = -O2 -Wall -DNDEBUG
DEBUG_FLAGS   = -g -O0 -Wall
RELEASE_EXEC  = hash_file
DEBUG_EXEC    = hash_file-dbg
SOURCE        = $(wildcard *.cpp)
LIBR          = -lcrypto++
all: debug release

debug: $(DEBUG_EXEC)

$(DEBUG_EXEC): $(SOURCE)
	g++ $(DEBUG_FLAGS) $(SOURCE) -o $(DEBUG_EXEC) $(LIBR)

release: $(RELEASE_EXEC)

$(RELEASE_EXEC): $(SOURCE)
	g++ $(RELEASE_FLAGS) $(SOURCE) -o $(RELEASE_EXEC) $(LIBR)

clean:
	rm -f $(RELEASE_EXEC) $(DEBUG_EXEC)

