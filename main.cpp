#include <stdio.h>
#include <string>
#include <time.h>
#include <assert.h>
#include <iostream>
#include <map>
#include <openssl/sha.h>

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#ifdef WIN32
	#include <Windows.h>
#else
	#include <pthread.h>
#endif

typedef unsigned char byte;

#ifdef WIN32
	typedef __int64 int64_t;
	typedef unsigned __int64 uint64_t;
#else
	typedef signed long long int64_t;
	typedef unsigned long long uint64_t;
#endif

using namespace std;

//const char* slat = "aae8123520fa8013";
//const char* passhash = "137afe87e9104665bd38a95ca3954e8d7eb6d12a";
const byte slat[] = {0xaa, 0xe8, 0x12, 0x35, 0x20, 0xfa, 0x80, 0x13};
const int slat_len = 8;
const byte passhash[] = {0x13, 0x7a, 0xfe, 0x87, 0xe9, 0x10, 0x46, 0x65, 0xbd, 0x38, 0xa9, 0x5c, 0xa3, 0x95, 0x4e, 0x8d, 0x7e, 0xb6, 0xd1, 0x2a};
const int passhash_len = 20;
const char* checkHash = "PasswordCheckHash";

SHA_CTX s_ctx;

void InitTestPassword()
{
	int check_hash_len = strlen(checkHash);
	SHA1_Init(&s_ctx);
	SHA1_Update(&s_ctx, checkHash, check_hash_len);
	SHA1_Update(&s_ctx, slat, slat_len);
}

bool TestPassword(char* text, int text_len)
{
	unsigned char md[SHA_DIGEST_LENGTH]; 
	SHA_CTX c = s_ctx;
	SHA1_Update(&c, text, text_len);
	SHA1_Final(md,&c);
	bool ret = !memcmp(md, passhash, passhash_len);
	return ret;
}

bool TestPassword2(char* text, int text_len)
{
	unsigned char md[SHA_DIGEST_LENGTH]; 
	SHA_CTX c;
	int check_hash_len = strlen(checkHash);
	SHA1_Init(&c);
	SHA1_Update(&c, checkHash, check_hash_len);
	SHA1_Update(&c, slat, slat_len);

	SHA1_Update(&c, text, text_len);
	SHA1_Final(md,&c);
	bool ret = !memcmp(md, passhash, passhash_len);
	return ret;
}

void SavePassword(char* filePath, char* password, int pass_len)
{
	FILE* file = fopen(filePath, "wb+");
	fwrite(password, pass_len, 1, file);
	fclose(file);
}

#define alphabet_len 62

const byte alphabet[alphabet_len] = {
	/*0-9*/ 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
	/*A-Z*/65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
	/*a-z*/97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122
};

class AlphaBetCalc
{
public:
	AlphaBetCalc(int64_t start, int64_t end)
	{
		_start = start;
		_end = end;
		_val = _start;
	}
	~AlphaBetCalc(){}
public:
	char* first()
	{
		_val = _start;
		memset(_text, 0, 15);
		memset(_text, 48, 12);
		for (int i = 0; i < 12; i++) {
			_pos_map[i] = 0;
		}

		int64_t val = _val;
		int pos = 0;
		while (val) {
			int bet_pos = val % alphabet_len;
			_text[pos] = alphabet[bet_pos];
			_pos_map[pos] = bet_pos;
			pos++;
			val /= alphabet_len;
		}
		return _text;
	}
	char* next()
	{
		_val++;
		if (_val <= _end) {
			int next_i = 0;
			for (int i = 0; i < 12; i++) {
				if (_pos_map[i] >= (alphabet_len -1)) {
					next_i = i;
					next_i++;
					break;
				}
			}
			_pos_map[next_i]++;
			int new_i_pos = _pos_map[next_i];
			if (next_i > 0) {
				//< 进位
				_pos_map[next_i - 1] = 0;
				_text[next_i - 1] = alphabet[0]; 
				_text[next_i] = alphabet[new_i_pos];
			} else {
				//< 个位加
				assert(next_i == 0);
				_text[next_i] = alphabet[new_i_pos];
			}
			return _text;
		}
		return 0;
	}
private:
	char _text[15];
	int _pos_map[12];

	uint64_t _val;
	uint64_t _start;
	uint64_t _end;
};

class RandomText
{
public:
	RandomText()
	{
		srand(time(NULL));
		memset(_text, 0, 15);
	}
	~RandomText(){}
public:
	char* next()
	{
		for (int i = 0; i < 12; i++) {
			_text[i] = alphabet[rand() % 62];
		}
		return _text;
	}
private:
	char _text[15];
};

typedef std::map<std::string, std::string> options_t;

void ParseOption(const string& opt, string& name, string& val)
{
	int pos = opt.find_first_of('=');
	if (pos == -1) {
		name = opt;
		val.clear();
	} else {
		name = opt.substr(0, pos);
		val = opt.substr(pos+1);
	}	
}

#ifdef WIN32

DWORD WINAPI RunHashCatRand(LPVOID lpParam)
{
	RandomText rand_text;
	for (int i = 0; i < 0xFFFFFFFF; i++) {
		char* text = rand_text.next();
		if (TestPassword2(text, 12)) {
			SavePassword("password.txt", text, 12);
			printf("%s Find\n", text);
			break;
		}
	}
	return 0;
}

#endif

typedef void(*HashThreadType)(void* user);

void HashThread(void* user)
{

}

void CreateHashThread(HashThreadType callback, void* user)
{

}

void usage()
{
	cerr << "hashtest version 1.2" << endl
		<< "Usage: hashtest action .." << endl
		<< "\trand [--thread=] [--time=]" << endl
		<< "\tattack [--thread=] [--time=]" << endl
		<< "\ttest --key=value" << endl
		<< "Params:" << endl
		<< "\t thread : run threads, default 1" << endl
		<< "\t time   : run time, default 60 seconds" << endl
		<< "\t key	  : test special(test action only)" << endl;
}

int main(int argc, char* argv[])
{
	InitTestPassword();

	if (argc < 2) {
		usage();
		return 1;
	}

	// parse command line
	string action = argv[1];
	options_t opts;
	for (int i = 2; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] == '-') {
			std::string name, val;
			ParseOption(argv[i], name, val);
			opts[name] = val;
		}
	}
	int thread_count = 1;
	int time_wait = 60 * 1000;
	if (opts.find("--thread") != opts.end()) {
		
	}
	if (opts.find("--time") != opts.end()) {

	}

	// do action
	if (action == "rand") {
		cerr << "run random" << endl;
		for (int i = 0; i < thread_count; i++) {
			CreateThread(NULL, 0, RunHashCatRand, (LPVOID)NULL, 0, NULL);
		}
		Sleep(time_wait);
		cerr << "rand time over..." << endl;
	} else if (action == "attack") {
		cerr << "run attack" << endl;
		//uint64_t count = 0xFFFFFFFFFFFFFFFF;
		//int startTime = GetTickCount();
		//AlphaBetCalc alpha_calc(0, 100000000);
		//char* text = alpha_calc.first();
		//do {
		//	//printf("%s\n", text);
		//	if (TestPassword2(text, 12)) {
		//		SavePassword("password.txt", text, 12);
		//		printf("%s Find\n", text);
		//		break;
		//	}
		//	text = alpha_calc.next();
		//} while (text);
		//int endTime = GetTickCount() - startTime;
		//printf("%d ms\n", endTime);
		//system("pause");	
	} else if (action == "test") {
		if (opts.find("--key") == opts.end()) {
			usage();
			return 1;
		}
		string key = opts["--key"];
		cerr << "run test, " << "key = " << key << endl;
		if (TestPassword2((char*)key.c_str(), key.length())) {
			cerr << "input key valid" << endl;
		} else {
			cerr << "input key invalid" << endl;
		}
	} else {
		usage();
		return 1;
	}
	system("pause");
	return 0;
}