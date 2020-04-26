CXXFLAGS += -O0 -g -fno-pie -fno-omit-frame-pointer -pthread -no-pie -Wall -Werror
LDLIBS += -ltbb
CFLAGS += -O0 -g -fno-pie -fno-omit-frame-pointer -pthread -no-pie -Wall -Werror

SRC = $(wildcard prog/*.cpp)
OBJ = $(patsubst prog/%.cpp,bin/%,$(SRC))

all: $(OBJ)
default: all

bin/%: prog/%.cpp
	$(CXX) $(CXXFLAGS) $< $(LDLIBS) -o $@

bin/%: prog/%.c
	$(CC) $(CFLAGS) $< -o $@
