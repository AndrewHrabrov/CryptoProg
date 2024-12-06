TARGET 		  = cipher
SOURCE        = $(wildcard *.cpp)
CCFlags       = -Wall
LDLIBS = -lcrypto++ -lboost_program_options

all:build
build:
	g++ $(CCFlags) $(SOURCE) -o $(TARGET) $(LDLIBS)
dbg:
	g++ -g $(SOURCE) -o $(TARGET)DBG
clean:
	rm -f $(TARGET) $(DEBUG_EXEC)



