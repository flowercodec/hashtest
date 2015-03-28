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
	#include <sys/time.h>
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

static char* s_slat_text = "aae8123520fa8013";
static char* s_passhash_text = "137afe87e9104665bd38a95ca3954e8d7eb6d12a";
static byte s_slat[] = {0xaa, 0xe8, 0x12, 0x35, 0x20, 0xfa, 0x80, 0x13};
static byte s_passhash[] = {0x13, 0x7a, 0xfe, 0x87, 0xe9, 0x10, 0x46, 0x65, 0xbd, 0x38, 0xa9, 0x5c, 0xa3, 0x95, 0x4e, 0x8d, 0x7e, 0xb6, 0xd1, 0x2a};

const int slat_len = 8;
const int passhash_len = 20;
const char* checkHash = "PasswordCheckHash";

SHA_CTX s_ctx;

void InitTestPassword()
{
	int check_hash_len = strlen(checkHash);
	SHA1_Init(&s_ctx);
	SHA1_Update(&s_ctx, checkHash, check_hash_len);
	SHA1_Update(&s_ctx, s_slat, slat_len);
}

bool TestPassword(char* text, int text_len)
{
	unsigned char md[SHA_DIGEST_LENGTH]; 
	SHA_CTX c = s_ctx;
	SHA1_Update(&c, text, text_len);
	SHA1_Final(md,&c);
	bool ret = !memcmp(md, s_passhash, passhash_len);
	return ret;
}

bool TestPassword2(char* text, int text_len)
{
	unsigned char md[SHA_DIGEST_LENGTH]; 
	SHA_CTX c;
	int check_hash_len = strlen(checkHash);
	SHA1_Init(&c);
	SHA1_Update(&c, checkHash, check_hash_len);
	SHA1_Update(&c, s_slat, slat_len);

	SHA1_Update(&c, text, text_len);
	SHA1_Final(md,&c);
	bool ret = !memcmp(md, s_passhash, passhash_len);
	return ret;
}

static int str_to_hex(const char *string, byte *cbuf, int len)
{
	BYTE high, low;
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) 
	{
		high = string[idx];
		low = string[idx+1];

		if(high>='0' && high<='9')
			high = high-'0';
		else if(high>='A' && high<='F')
			high = high - 'A' + 10;
		else if(high>='a' && high<='f')
			high = high - 'a' + 10;
		else
			return -1;

		if(low>='0' && low<='9')
			low = low-'0';
		else if(low>='A' && low<='F')
			low = low - 'A' + 10;
		else if(low>='a' && low<='f')
			low = low - 'a' + 10;
		else
			return -1;

		cbuf[ii++] = high<<4 | low;
	}
	return 0;
}

void UpdatePassHashAndSlat(string& passhash, string& slat)
{
	str_to_hex(passhash.c_str(), s_passhash, passhash.length());
	str_to_hex(slat.c_str(), s_slat, slat.length());
}

void SavePassword(char* filePath, char* password, int pass_len)
{
	FILE* file = fopen(filePath, "wb+");
	fwrite(password, pass_len, 1, file);
	fclose(file);
}

typedef map<string, string> options_t;

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

//////////////////////////////////////////////////////////////////////////
typedef void(*HashThreadType)(void* user);

struct HashThreadContext
{
	HashThreadType thread;
	void* user;
};

struct HashRange
{
	uint64_t start;
	uint64_t end;
};

void RunHashCatRand(void* user)
{
	RandomText rand_text;
	for (int i = 0; i < 0xFFFFFFFF; i++) {
		char* text = rand_text.next();
		if (TestPassword(text, 12)) {
			SavePassword("password.txt", text, 12);
			printf("%s Find\n", text);
			break;
		}
	}
}

void RunHashCatRange(void* user)
{
	HashRange* range = (HashRange*)user;
	AlphaBetCalc alpha_calc(range->start, range->end);
	char* text = alpha_calc.first();
	do {
		if (TestPassword(text, 12)) {
			SavePassword("password.txt", text, 12);
			printf("%s Find\n", text);
			break;
		}
		text = alpha_calc.next();
	} while (text);
}

//////////////////////////////////////////////////////////////////////////
/// platform begin
#ifdef WIN32
DWORD WINAPI Win32ThreadExecute(LPVOID lpParam)
{
	HashThreadContext* ctx = (HashThreadContext*)lpParam;
	ctx->thread(ctx->user);
	return 0;
}
#else
void* pthreadExecute(void *arg)
{
	HashThreadContext* ctx = (HashThreadContext*)arg;
	ctx->thread(ctx->user);
	return 0;
}
#endif

void CreateHashThread(HashThreadContext* thread_ctx)
{
#ifdef WIN32
	CreateThread(NULL, 0, Win32ThreadExecute, (LPVOID)thread_ctx, 0, NULL);
#else
	pthread_t tid;
	pthread_create(&tid, NULL, pthreadExecute, thread_ctx)
#endif
}

void NativeSleep(unsigned int ms)
{
#ifdef WIN32
	Sleep(ms);
#else
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000 * 1000 };
	nanosleep(&ts, NULL);
#endif
}

/// platform end
//////////////////////////////////////////////////////////////////////////


void usage()
{
	cerr << "hashtest version 1.2" << endl
		<< "Usage: hashtest action .." << endl
		<< "\trand [--thread=] [--time=] [--passhash=] [--slat=]" << endl
		<< "\tattack [--thread=] [--time=] [--passhash=] [--slat=]" << endl
		<< "\ttest --key=value [--passhash=] [--slat=]" << endl
		<< "Params:" << endl
		<< "\tthread : run threads, default 1" << endl
		<< "\ttime   : run time, default 60 seconds" << endl
		<< "\tpasshash : len 40 default:" << s_passhash_text << endl
		<< "\tslat : len 16 default:" << s_slat_text << endl
		<< "\tkey : test special(test action only)" << endl;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		usage();
		return 1;
	}

	// parse command line
	string action = argv[1];
	options_t opts;
	for (int i = 2; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] == '-') {
			string name, val;
			ParseOption(argv[i], name, val);
			opts[name] = val;
		}
	}
	int thread_count = 1;
	int time_wait = 60;
	if (opts.find("--thread") != opts.end()) {
		string thread = opts["--thread"];
		sscanf(thread.c_str(), "%d", &thread_count);
	}
	if (opts.find("--time") != opts.end()) {
		string time = opts["--time"];
		sscanf(time.c_str(), "%d", &time_wait);
	}
	if (opts.find("--passhash") != opts.end() &&
		opts.find("--slat") != opts.end()) {
		string passhash = opts["--passhash"];
		string slat = opts["--slat"];
		if (passhash.length() != 40 ||
			slat.length() != 16) {
			usage();
			return 1;
		}
		UpdatePassHashAndSlat(passhash, slat);
	}

	InitTestPassword();

	// do action
	if (action == "rand") {
		cerr << "run random" << ", thread = " << thread_count << ", time(seconds) = " << time_wait << endl;
		for (int i = 0; i < thread_count; i++) {
			///< ctx memory leak!
			HashThreadContext* ctx = new HashThreadContext;
			ctx->thread = RunHashCatRand;
			ctx->user = NULL;
			CreateHashThread(ctx);
		}
		NativeSleep((unsigned int)1000 * time_wait);
		cerr << "rand time over..." << endl;
	} else if (action == "attack") {
		cerr << "run attack" << ", thread = " << thread_count << ", time(seconds) = " << time_wait << endl;
		uint64_t count = 0xFFFFFFFFFFFFFFFF;	///< FIXME not enough
		uint64_t ev_count = count / thread_count;
		for (int i = 0; i < thread_count; i++) {
			///< ctx,range memory leak!
			HashThreadContext* ctx = new HashThreadContext;
			HashRange* range = new HashRange;
			range->start = ev_count * i;
			range->end   = ev_count * (i + 1);
			ctx->thread = RunHashCatRange;
			ctx->user = range;
			CreateHashThread(ctx);
		}
		NativeSleep((unsigned int)1000 * time_wait);
		cerr << "attack time over..." << endl;
	} else if (action == "test") {
		if (opts.find("--key") == opts.end()) {
			usage();
			return 1;
		}
		string key = opts["--key"];
		cerr << "run test, " << "key = " << key << endl;
		if (TestPassword((char*)key.c_str(), key.length())) {
			cerr << "input key good" << endl;
		} else {
			cerr << "input key bad" << endl;
		}
	} else {
		usage();
		return 1;
	}
	system("pause");
	return 0;
}