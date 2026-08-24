CXX := clang++
TARGET := pswd_gen
SOURCE := main.cpp
WORDLIST := $(CURDIR)/data/eff_large_wordlist.txt

CPPFLAGS := -DDICEWARE_WORDLIST_PATH=\"$(WORDLIST)\"
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDLIBS := -lcrypto

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SOURCE) $(WORDLIST)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCE) $(LDLIBS) -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
