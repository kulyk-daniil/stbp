#include <windows.h>
#include <iostream>
#include <processthreadsapi.h>
#include <libloaderapi.h>


extern "C" {
	typedef unsigned int (*CRC_16_IBM)(int len, int param_2);
	typedef int (*getIV)(char* param_1);
	typedef int (*getK)(char* param_1);
	typedef int (*enc)(byte* param_1, int param_3, int param_2);
	typedef int (*dec)(byte* param_1, int param_2, int param_3);
}


unsigned int MY_CRC_16_IBM(int, int);
int My_getIV(char*);

int main()
{
	auto hdl = LoadLibraryA("n3k_comm.dll");
	if (hdl)
	{
		auto crc16Func = reinterpret_cast<CRC_16_IBM>(GetProcAddress(hdl, "CRC_16_IBM"));
		if (crc16Func) {
			auto dllResult = crc16Func(16, 0x1000b040);
			auto myResult = MY_CRC_16_IBM(16, 0x1000b040);
			std::cout << "DLL CRC_16_IBM result = " << dllResult << std::endl;
			std::cout << "My CRC_16_IBM result = " << myResult << std::endl;
		}
		else {
			std::cout << "Function CRC_16_IBM not found!" << std::endl;
		}

		auto getIVFunc = reinterpret_cast<getIV>(GetProcAddress(hdl, "getIV"));
		if (getIVFunc) {
			char ivStr[17] = { 0 };
			auto r = getIVFunc(ivStr);
			char ivStr2[17] = { 0 };
			auto r2 = My_getIV(ivStr2);
			std::cout << "DLL getIV result = " << ivStr << std::endl;
			std::cout << "My getIV result = " << ivStr2 << std::endl;
		}
		else {
			std::cout << "Function getIV not found!" << std::endl;
		}
		auto getKFunc = reinterpret_cast<getK>(GetProcAddress(hdl, "getK"));
		if (getKFunc) {
			char kStr[17] = { 0 };
			auto r = getKFunc(kStr);
			std::cout << "Dll getK result = " << kStr << std::endl;
		}
		else {
			std::cout << "Function getK not found!" << std::endl;
		}

		auto encFunc = reinterpret_cast<enc>(GetProcAddress(hdl, "enc"));
		auto decFunc = reinterpret_cast<dec>(GetProcAddress(hdl, "dec"));
		if (encFunc && decFunc) {
			byte str[16] = { 'H', 'E', 'L', 'L', '\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0' };
			int key = 0x1000b040;
			auto r = encFunc(str, 16, key);
			std::cout << "DLL enc result = " << str << std::endl;
			auto r2 = decFunc(str, 16, key);
			std::cout << "DLL dec result = " << str << std::endl;
		}
		else {
			std::cout << "Function enc and dec not found!" << std::endl;
		}


		FreeLibrary(hdl);
	}
	else {
		std::cout << "Library not found!" << std::endl;
	}

}


unsigned int MY_CRC_16_IBM(int len, int address)
{
	unsigned int result = 0;

	for (int i = 0; i < len; i++)
	{
		result ^= *(byte*)(i + address);
		for (int j = 0; j < 8; j++)
		{
			if ((result & 1) != 0)
				result ^= 0x14002;
			result >>= 1;
		}
	}
	return result;
}

int My_getIV(char* param_1)
{
	char* dest;

	for (int i = 0; i < 16; i++)
	{
		dest = (char*)(i + param_1);
		*dest = (dest[(int)0x1000b040 - (int)param_1] - i) - 1;
	}

	return 1;
}