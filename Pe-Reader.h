#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <iostream>
#include <exception>
#include <map>
#include <string>
#include <typeinfo>

#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)

enum Colors {
	Black = 0 , 
	Red = FOREGROUND_RED , 
	Green = FOREGROUND_GREEN , 
	Yellow = FOREGROUND_RED |  FOREGROUND_GREEN | FOREGROUND_INTENSITY , 
	Blue = FOREGROUND_BLUE , 
	Grey = FOREGROUND_INTENSITY , 
	Cyan = FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE  , 
	Magenta = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE
};



class Console {
private:
	HANDLE hStdOutput;
	CONSOLE_SCREEN_BUFFER_INFOEX OldScreenBufferInfoEx;
public:
	Console() {
		hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		GetConsoleScreenBufferInfoEx(hStdOutput, &OldScreenBufferInfoEx);

		CONSOLE_FONT_INFOEX Font;
		Font.cbSize = sizeof(CONSOLE_FONT_INFOEX);
		Font.nFont = 0;
		Font.dwFontSize.X = 0;
		Font.dwFontSize.Y = 20;
		Font.FontFamily = FF_DONTCARE;
		Font.FontWeight = FW_HEAVY;
		std::wcscpy(Font.FaceName, L"Consolas");
		SetCurrentConsoleFontEx(hStdOutput, FALSE, &Font);
	}

	~Console() {
		SetConsoleTextAttribute(hStdOutput, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		CONSOLE_FONT_INFOEX Font;
		Font.nFont = 0;
		Font.dwFontSize.X = 0;
		Font.dwFontSize.Y = 14;
		Font.FontFamily = FF_DONTCARE;
		Font.FontWeight = FW_HEAVY;
		std::wcscpy(Font.FaceName, L"Consolas");
		SetCurrentConsoleFontEx(hStdOutput, FALSE, &Font);
		CloseHandle(hStdOutput);
	}

	void Print(Colors color) {
		SetConsoleTextAttribute(hStdOutput , color);
	}

	template <typename T> void Print(T t) {
		std::cout << t;
	}
};

class MappedFile {
private:
	HANDLE hFile;
	HANDLE hMapping;
	LPBYTE lpFile;
	wchar_t szFileName[256];
public:

	void GetFileName() {
		OPENFILENAME ofn;
		HANDLE retHandle;
		ZeroMemory(szFileName, sizeof(szFileName));
		ZeroMemory(&ofn, sizeof(OPENFILENAME));
		ofn.lStructSize = sizeof(OPENFILENAME);
		ofn.hwndOwner = NULL;
		ofn.lpstrFile = szFileName;
		ofn.nMaxFile = sizeof(szFileName);
		ofn.lpstrFilter = L"Executable\0*.exe;*.dll\0\0";
		ofn.nFilterIndex = 1;
		ofn.lpstrFileTitle = NULL;
		ofn.nMaxFileTitle = 0;
		ofn.lpstrInitialDir = NULL;
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
		if (!GetOpenFileNameW(&ofn)) {
			MessageBox(NULL, L"Error Occupation", 0, 0);
			ExitProcess(CommDlgExtendedError());
		}
	}

	MappedFile() {
		this->GetFileName();
		hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE) {
			MessageBox(NULL, L"Error Occupation", 0, 0);
			ExitProcess(-1);
		}

		DWORD dwFileSize = GetFileSize(hFile, NULL);
		hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

		if (hMapping == NULL) {
			CloseHandle(hFile);
			MessageBox(NULL, L"Can't create file mapping", 0, 0);
			ExitProcess(-1);
		}

		lpFile = LPBYTE(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, dwFileSize));
		if (lpFile == NULL) {
			CloseHandle(hMapping);
			CloseHandle(hFile);
			MessageBox(NULL, L"Can't map view of file!", 0, 0);
			ExitProcess(GetLastError());
		}
	}

	LPBYTE getViewOfFile() {
		return lpFile;
	}

	~MappedFile() {
		UnmapViewOfFile(lpFile);
		CloseHandle(hMapping);
		CloseHandle(hFile);
	}
};

class PeParser {
private:
	Console cons;
	LPBYTE lpFile = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PDWORD Signature  = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL; PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL; 
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	std::map<int, std::string> FILE_HEADER_MACHINE = {
		{0x14c , "IMAGE_FILE_MACHINE_I386"} ,
		{0x200 , "IMAGE_FILE_MACHINE_IA64"} ,
		{0x8664 , "IMAGE_FILE_MACHINE_AMD64"}
	};
	
	std::map<int, std::string> FILE_HEADER_CHARACTERISTICS = {
		{ 0x1 , "IMAGE_FILE_RELOCS_STROPPED"} ,
		{0x2 , "IMAGE_FILE_EXECUTABLE_IMAGE"} ,
		{0x4 , "IMAGE_FILE_LINE_NUMS_STRIPPED"} ,
		{0x8 , "IMAGE_FILE_LOCAL_SYMS_STRIPPED"} ,
		{0x10 , "IMAGE_FILE_AGGRESIVE_WS_TRIM"} ,
		{0x20 , "IMAGE_FILE_LARGE_ADDRESS_AWARE"} ,
		{0x80 , "IMAGE_FILE_BYTES_REVERSED_LO"} ,
		{0x100 , "IMAGE_FILE_32BIT_MACHINE"} ,
		{0x200 , "IMAGE_FILE_DEBUG_STRIPPED"} ,
		{0x400 , "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"} ,
		{0x800 , "IMAGE_FILE_NET_RUN_FROM_SWAP"} ,
		{0x1000 , "IMAGE_FILE_SYSTEM"} ,
		{0x2000 , "IMAGE_FILE_DLL"} ,
		{0x4000 , "IMAGE_FILE_UP_SYSTEM_ONLY"} ,
		{0x8000 , "IMAGE_FILE_BYTES_REVERSED_HI"}
	};

	std::map<int, std::string> OPTIONAL_HEADER_SUBSYSTEM = {
		{0x0 , "IMAGE_SUBSYSTEM_UNKNOWN"} ,
		{0x1 , "IMAGE_SUBSYSTEM_NATIVE"} ,
		{0x2 , "IMAGE_SUBSYSTEM_WINDOWS_GUI"} ,
		{0x3 , "IMAGE_SUBSYSTEM_WINDOWS_CUI"} ,
		{0x5 , "IMAGE_SUBSYSTEM_OS2_CUI"} ,
		{0x7 , "IMAGE_SUBSYSTEM_POSIX_CUI"} ,
		{0x9 , "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"} ,
		{0x10 , "IMAGE_SUBSYSTEM_EFI_APPLICATION"} ,
		{0x11 , "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"} ,
		{0x12 , "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"} ,
		{0x13 , "IMAGE_SUBSYSTEM_EFI_ROM"} ,
		{0x14 , "IMAGE_SUBSYSTEM_XBOX"} ,
		{0x16 , "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"}

	};

	std::map<int, std::string> OPTIONAL_HEADER_DLLCHARACTERISTICS = {
		{0x20 , "IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA"} ,
		{0x40 , "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"} ,
		{0x80 , "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"} ,
		{0x100 , "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"} ,
		{0x200 , "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"} ,
		{0x400 , "IMAGE_DLLCHARACTERISTICS_NO_SEH"} ,
		{0x800 , "IMAGE_DLLCHARACTERISTICS_NO_BIND"} ,
		{0x1000 , "IMAGE_DLL_CHARACTERISTICS_APPCONTAINER"} ,
		{0x2000 , "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"} ,
		{0x4000 , "IMAGE_DLL_CHARACTERISTICS_GUARD_CF"} ,
		{0x8000 , "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"}
	};

	std::map<int, std::string> SECTION_HEADER_CHARACTERISTICS = {
		{0x8 , "IMAGE_SCN_TYPE_NO_PAD"} ,
		{0x20 , "IMAGE_SCN_CNT_CODE"} ,
		{0x40 ,"IMAGE_SCN_CNT_INITIALIZED_DATA"} ,
		{0x80 , "IMAGE_SCN_CNT_UNINITIALIZED_DATA"},
		{0x100 , "IMAGE_SCN_LNK_OTHER"} ,
		{0x200 , "IMAGE_SCN_LNK_INFO"} ,
		{0x800 , "IMAGE_SCN_LNK_REMOVE"},
		{0x1000 , "IMAGE_SCN_LNK_COMDAT"},
		{0x4000 , "IMAGE_SCN_NO_DEFER_SPEC_EXC"},
		{0x8000 , "IMAGE_SCN_GPREL"} ,
		{0x20000 , "IMAGE_SCN_MEM_PURGEABLE"} , 
		{0x40000 , "IMAGE_SCN_MEM_LOCKED"} , 
		{0x80000 , "IMAGE_SCN_MEM_PRELOAD"} , 
		{0x100000 , "IMAGE_SCN_ALIGN_1BYTES"} , 
		{0x200000 , "IMAGE_SCN_ALIGN_2BYTES"} ,
		{0x300000 , "IMAGE_SCN_ALIGN_4BYTES"} ,
		{0x400000 , "IMAGE_SCN_ALIGN_8BYTES"} ,
		{0x500000 , "IMAGE_SCN_ALIGN_16BYTES"} ,
		{0x600000 , "IMAGE_SCN_ALIGN_32BYTES"} ,
		{0x700000 , "IMAGE_SCN_ALIGN_64BYTES"} ,
		{0x800000 , "IMAGE_SCN_ALIGN_128BYTES"} ,
		{0x900000 , "IMAGE_SCN_ALIGN_256BYTES"} ,
		{0xa00000 , "IMAGE_SCN_ALIGN_512BYTES"} ,
		{0xb00000 , "IMAGE_SCN_ALIGN_1024BYTES"} ,
		{0xc00000 , "IMAGE_SCN_ALIGN_2048BYTES"} ,
		{0xd00000 , "IMAGE_SCN_ALIGN_4096BYTES"} ,
		{0xe00000 , "IMAGE_SCN_ALIGN_8192BYTES"} ,
		{0x1000000 , "IMAGE_SCN_LNK_NRELOC_OVFL"} , 
		{0x2000000 , "IMAGE_SCN_MEM_DISCARDABLE"} ,
		{0x4000000 , "IMAGE_SCN_MEM_NOT_CACHED"} ,
		{0x8000000 , "IMAGE_SCN_MEM_NOT_PAGED"} ,
		{0x10000000 , "IMAGE_SCN_MEM_SHARED"} ,
		{0x20000000 , "IMAGE_SCN_MEM_EXECUTE"} ,
		{0x40000000 , "IMAGE_SCN_MEM_READ"} ,
		{0x80000000 , "IMAGE_SCN_MEM_WRITE"} ,
	};

public:

	int defSection(DWORD rva) {
		for (int i = 0; i < pFileHeader->NumberOfSections; ++i) {
			DWORD start = pSectionHeader[i].VirtualAddress;
			DWORD end;
			if (pOptionalHeader64 == NULL) {
				end = start + ALIGN_UP(pSectionHeader[i].VirtualAddress, pOptionalHeader32->SectionAlignment) - 1;
			}
			else {
				end = start + ALIGN_UP(pSectionHeader[i].VirtualAddress, pOptionalHeader64->SectionAlignment) - 1;
			}

			if (rva >= start && rva <= end) {
				return i;
			}
		}
		return -1;
	}

	int RvaToRaw(DWORD rva) {
		int indexSection = defSection(rva);
		if (indexSection == -1) {
			MessageBox(NULL, L"Error in address transliting", 0, 0);
			ExitProcess(-1);
		}
		return rva - pSectionHeader[indexSection].VirtualAddress + pSectionHeader[indexSection].PointerToRawData;
	}
	
	PeParser(LPBYTE _lpFile) : lpFile(_lpFile) {

		pDosHeader = PIMAGE_DOS_HEADER(lpFile);
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			throw std::exception("This file is not executable");
		}

		Signature = PDWORD(lpFile + pDosHeader->e_lfanew);
		if (*Signature != IMAGE_NT_SIGNATURE) {
			throw std::exception("This file is not executable");
		}

		pFileHeader = PIMAGE_FILE_HEADER(lpFile + pDosHeader->e_lfanew + 4);

		if (pFileHeader->Machine == 0x14c) {
			pOptionalHeader32 = PIMAGE_OPTIONAL_HEADER32(lpFile + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER ));
			pSectionHeader = PIMAGE_SECTION_HEADER(lpFile + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
			if (pOptionalHeader32 -> DataDirectory[0].VirtualAddress != 0) {
				pExportDirectory = PIMAGE_EXPORT_DIRECTORY(lpFile + RvaToRaw(pOptionalHeader32->DataDirectory[0].VirtualAddress));
			}
		}
		else {
			pOptionalHeader64 = PIMAGE_OPTIONAL_HEADER64(lpFile + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
			pSectionHeader = PIMAGE_SECTION_HEADER(lpFile + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +  sizeof(IMAGE_OPTIONAL_HEADER64));
			if (pOptionalHeader64->DataDirectory[0].VirtualAddress != 0) {
				pExportDirectory = PIMAGE_EXPORT_DIRECTORY(lpFile + RvaToRaw(pOptionalHeader64->DataDirectory[0].VirtualAddress));
			}
		}
	}

	void print() {

		// IMAGE_DOS_HEADER
		cons.Print(Colors::Red);
		cons.Print("================================================================\n");
		cons.Print(Colors::Green); cons.Print("DOS_HEADER:\n");
		cons.Print(Colors::Yellow); cons.Print("\te_magic: "); cons.Print(Colors::Grey); cons.Print("MZ\n");
		cons.Print(Colors::Yellow); cons.Print("\te_cblp: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_cblp);
		cons.Print(Colors::Yellow); cons.Print("\n\te_cp: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_cp);
		cons.Print(Colors::Yellow); cons.Print("\n\te_crlc: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_crlc);
		cons.Print(Colors::Yellow); cons.Print("\n\te_cparhdr: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_cparhdr);
		cons.Print(Colors::Yellow); cons.Print("\n\te_minalloc: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_minalloc);
		cons.Print(Colors::Yellow); cons.Print("\n\te_maxalloc: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_maxalloc);
		cons.Print(Colors::Yellow); cons.Print("\n\te_ss: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_ss);
		cons.Print(Colors::Yellow); cons.Print("\n\te_sp: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_sp);
		cons.Print(Colors::Yellow); cons.Print("\n\te_csum: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_csum);
		cons.Print(Colors::Yellow); cons.Print("\n\te_ip: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_ip);
		cons.Print(Colors::Yellow); cons.Print("\n\te_cs: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_cs);
		cons.Print(Colors::Yellow); cons.Print("\n\te_lfarlc: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_lfarlc);
		cons.Print(Colors::Yellow); cons.Print("\n\te_ovno: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_ovno);
		cons.Print(Colors::Yellow); cons.Print("\n\te_oemid: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_oemid);
		cons.Print(Colors::Yellow); cons.Print("\n\te_oeminfo: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_oeminfo);
		cons.Print(Colors::Yellow); cons.Print("\n\te_lfanew: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pDosHeader->e_lfanew);
		cons.Print(Colors::Red);
		cons.Print("\n\n================================================================\n");

		//IMAGE_FILE_HEADER
		cons.Print(Colors::Green); cons.Print("FILE_HEADER:\n");
		cons.Print(Colors::Yellow); cons.Print("\tSignature: "); cons.Print(Colors::Grey); cons.Print("PE");
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("Machine: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print(FILE_HEADER_MACHINE[pFileHeader->Machine]);
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("NumberOfSections: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pFileHeader->NumberOfSections);
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("TimeDateStamp: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pFileHeader->TimeDateStamp);
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("PointerToSymbolTable: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pFileHeader->PointerToSymbolTable);
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("NumberOfSymbols: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pFileHeader->NumberOfSymbols);
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("SizeOfOptionalHeader: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pFileHeader->SizeOfOptionalHeader);
		cons.Print(Colors::Yellow); cons.Print("\n\t"); cons.Print("Characteristics: "); cons.Print(Colors::Grey);
		for (std::map<int, std::string>::iterator iter = FILE_HEADER_CHARACTERISTICS.begin(); iter != FILE_HEADER_CHARACTERISTICS.end(); ++iter) {
			if ((pFileHeader->Characteristics & iter->first) == iter->first) {
				cons.Print(iter->second); cons.Print(" | ");
			}
		}
		cons.Print(Colors::Red); cons.Print("\n\n================================================================\n");

		//IMAGE_OPTIONAL_HEADER
		if (pOptionalHeader64 == NULL) {
			cons.Print(Colors::Green); cons.Print("OPTIONAL_HEADER32\n");
			cons.Print(Colors::Yellow); cons.Print("\tMagic: "); cons.Print(Colors::Grey); cons.Print("PE32");
			cons.Print(Colors::Yellow); cons.Print("\n\tLinkerVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec); cons.Print((WORD)pOptionalHeader32->MajorLinkerVersion); cons.Print("."); cons.Print((WORD)pOptionalHeader32->MinorLinkerVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfCode: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfCode);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfInitializedData: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfInitializedData);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfUninitializedData: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfUninitializedData);
			cons.Print(Colors::Yellow); cons.Print("\n\tAddressOfEntryPoint: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->AddressOfEntryPoint);
			cons.Print(Colors::Yellow); cons.Print("\n\tBaseOfCode: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->BaseOfCode);
			cons.Print(Colors::Yellow); cons.Print("\n\tBaseOfData: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32 ->BaseOfData);
			cons.Print(Colors::Yellow); cons.Print("\n\tImageBase: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->ImageBase);
			cons.Print(Colors::Yellow); cons.Print("\n\tSectionAlignment: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SectionAlignment);
			cons.Print(Colors::Yellow); cons.Print("\n\tFileAlignment: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->FileAlignment);
			cons.Print(Colors::Yellow); cons.Print("\n\tOperatingSystemVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec);  cons.Print(pOptionalHeader32->MajorOperatingSystemVersion); cons.Print("."); cons.Print(pOptionalHeader32->MinorOperatingSystemVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tImageVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec);  cons.Print(pOptionalHeader32->MajorImageVersion); cons.Print("."); cons.Print(pOptionalHeader32->MinorImageVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tSubsystemVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec);  cons.Print(pOptionalHeader32->MajorSubsystemVersion); cons.Print("."); cons.Print(pOptionalHeader32->MinorSubsystemVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tWin32VersionValue: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->Win32VersionValue);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfImage: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfImage);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfHeaders: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfHeaders);
			cons.Print(Colors::Yellow); cons.Print("\n\tCheckSum: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->CheckSum);
			cons.Print(Colors::Yellow); cons.Print("\n\tSubsystem: "); cons.Print(Colors::Grey);  cons.Print(OPTIONAL_HEADER_SUBSYSTEM[pOptionalHeader32->Subsystem]);
			cons.Print(Colors::Yellow); cons.Print("\n\tDllCharacteristics: "); cons.Print(Colors::Grey);
			for (std::map<int, std::string>::iterator iter = OPTIONAL_HEADER_DLLCHARACTERISTICS.begin(); iter != OPTIONAL_HEADER_DLLCHARACTERISTICS.end(); ++iter) {
				if ((pOptionalHeader32->DllCharacteristics & iter->first) == iter->first) {
					cons.Print(iter->second); cons.Print(" | ");
				}
			}
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfStackReserve: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfStackReserve);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfStackCommit: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfStackCommit);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfHeapReserve: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfHeapReserve);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfHeapCommit: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->SizeOfHeapCommit);
			cons.Print(Colors::Yellow); cons.Print("\n\tLoaderFlags: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->LoaderFlags);
			cons.Print(Colors::Yellow); cons.Print("\n\tNumberOfRvaAndSizes: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader32->NumberOfRvaAndSizes);

			cons.Print(Colors::Red); cons.Print("\n\n================================================================\n");
		}
		else {
			cons.Print(Colors::Green); cons.Print("OPTIONAL_HEADER64\n");
			cons.Print(Colors::Yellow); cons.Print("\tMagic: "); cons.Print(Colors::Grey); cons.Print("PE32+");
			cons.Print(Colors::Yellow); cons.Print("\n\tLinkerVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec); cons.Print((WORD)pOptionalHeader64->MajorLinkerVersion); cons.Print("."); cons.Print((WORD)pOptionalHeader64->MinorLinkerVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfCode: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfCode);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfInitializedData: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfInitializedData);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfUninitializedData: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfUninitializedData);
			cons.Print(Colors::Yellow); cons.Print("\n\tAddressOfEntryPoint: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->AddressOfEntryPoint);
			cons.Print(Colors::Yellow); cons.Print("\n\tBaseOfCode: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->BaseOfCode);
			cons.Print(Colors::Yellow); cons.Print("\n\tImageBase: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->ImageBase);
			cons.Print(Colors::Yellow); cons.Print("\n\tSectionAlignment: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SectionAlignment);
			cons.Print(Colors::Yellow); cons.Print("\n\tFileAlignment: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->FileAlignment);
			cons.Print(Colors::Yellow); cons.Print("\n\tOperatingSystemVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec);  cons.Print(pOptionalHeader64->MajorOperatingSystemVersion); cons.Print("."); cons.Print(pOptionalHeader64->MinorOperatingSystemVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tImageVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec);  cons.Print(pOptionalHeader64->MajorImageVersion); cons.Print("."); cons.Print(pOptionalHeader64->MinorImageVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tSubsystemVersion: "); cons.Print(Colors::Grey); cons.Print(std::dec);  cons.Print(pOptionalHeader64->MajorSubsystemVersion); cons.Print("."); cons.Print(pOptionalHeader64->MinorSubsystemVersion);
			cons.Print(Colors::Yellow); cons.Print("\n\tWin32VersionValue: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->Win32VersionValue);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfImage: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfImage);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfHeaders: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfHeaders);
			cons.Print(Colors::Yellow); cons.Print("\n\tCheckSum: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->CheckSum);
			cons.Print(Colors::Yellow); cons.Print("\n\tSubsystem: "); cons.Print(Colors::Grey);  cons.Print(OPTIONAL_HEADER_SUBSYSTEM[pOptionalHeader64->Subsystem]);
			cons.Print(Colors::Yellow); cons.Print("\n\tDllCharacteristics: "); cons.Print(Colors::Grey);
			for (std::map<int, std::string>::iterator iter = OPTIONAL_HEADER_DLLCHARACTERISTICS.begin(); iter != OPTIONAL_HEADER_DLLCHARACTERISTICS.end(); ++iter) {
				if ((pOptionalHeader64->DllCharacteristics & iter->first) == iter->first) {
					cons.Print(iter->second); cons.Print(" | ");
				}
			}
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfStackReserve: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfStackReserve);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfStackCommit: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfStackCommit);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfHeapReserve: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfHeapReserve);
			cons.Print(Colors::Yellow); cons.Print("\n\tSizeOfHeapCommit: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->SizeOfHeapCommit);
			cons.Print(Colors::Yellow); cons.Print("\n\tLoaderFlags: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->LoaderFlags);
			cons.Print(Colors::Yellow); cons.Print("\n\tNumberOfRvaAndSizes: "); cons.Print(Colors::Grey); cons.Print(std::hex); cons.Print("0x"); cons.Print(pOptionalHeader64->NumberOfRvaAndSizes);

			cons.Print(Colors::Red); cons.Print("\n\n================================================================\n");
		}

		//SECTIONS
		cons.Print(Colors::Cyan); cons.Print("SECTIONS:\n");
		for (int i = 0; i < pFileHeader->NumberOfSections; ++i) {
			//pSectionHeader[i]
			cons.Print(Colors::Green); cons.Print("\t"); cons.Print(pSectionHeader[i].Name); cons.Print(":\n");
			cons.Print(Colors::Yellow); cons.Print("\t\tVirtualSize: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].Misc.VirtualSize);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tVirtualAddress: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].VirtualAddress);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tSizeOfRawData: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].SizeOfRawData);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tPointerToRawData: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].PointerToRawData);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tPointerToRelocations: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].PointerToRelocations);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tPointerToLinenumbers: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].PointerToLinenumbers);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tNumberOfRelocations: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].NumberOfRelocations);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tNumberOfLinenumbers: "); cons.Print(Colors::Grey);  cons.Print(std::hex); cons.Print("0x"); cons.Print(pSectionHeader[i].NumberOfLinenumbers);
			cons.Print(Colors::Yellow); cons.Print("\n\t\tCharacteristics: "); cons.Print(Colors::Grey);
			for (std::map<int, std::string>::iterator iter = SECTION_HEADER_CHARACTERISTICS.begin(); iter != SECTION_HEADER_CHARACTERISTICS.end(); ++iter) {
				if ((pSectionHeader[i].Characteristics & iter->first) == iter->first) {
					cons.Print(iter->second); cons.Print(" | ");
				}
			}
			cons.Print("\n\n");
		}
		cons.Print(Colors::Red); cons.Print("\n\n================================================================\n");

		//EXPORT
		cons.Print(Colors::Magenta); cons.Print("EXPORT:\n");
		cons.Print(Colors::Green); cons.Print("\t");
		if (pExportDirectory) {
			cons.Print((char*)(lpFile + RvaToRaw(pExportDirectory->Name))); cons.Print(" : \n");
			DWORD dwExportDirRvaStart; DWORD dwExportDirRvaEnd;
			if (pOptionalHeader64 == NULL) {
				dwExportDirRvaStart = pOptionalHeader32->DataDirectory[0].VirtualAddress;
				dwExportDirRvaEnd = dwExportDirRvaStart + pOptionalHeader32->DataDirectory[0].Size;
			}
			else {
				dwExportDirRvaStart = pOptionalHeader64->DataDirectory[0].VirtualAddress;
				dwExportDirRvaEnd = dwExportDirRvaStart + pOptionalHeader64->DataDirectory[0].Size;
			}

			LPDWORD lpFuncTable = LPDWORD(lpFile + RvaToRaw(pExportDirectory->AddressOfFunctions));
			LPDWORD lpNameTable = LPDWORD(lpFile + RvaToRaw(pExportDirectory->AddressOfNames));
			LPDWORD lpOrdTable = LPDWORD(lpFile + RvaToRaw(pExportDirectory->AddressOfNameOrdinals));


			for (UINT i = 0 ; i < pExportDirectory ->NumberOfNames ; ++i){
				DWORD dwOrd =  i + pExportDirectory->Base;
				cons.Print(Colors::Red); cons.Print("\t\t"); cons.Print((char*)(lpFile + RvaToRaw(lpNameTable[i]))); cons.Print(" : \n");
				cons.Print(Colors::Yellow);  cons.Print("\t\t\tOrdinal: "); cons.Print(std::dec);  cons.Print(Colors::Grey);  cons.Print(dwOrd); cons.Print("\n");
				cons.Print(Colors::Yellow);  cons.Print("\t\t\tAddress: "); cons.Print(std::hex);  cons.Print(Colors::Grey);
				DWORD Rva = lpFuncTable[i];
				if (Rva >= dwExportDirRvaStart && Rva <= dwExportDirRvaEnd) {
					cons.Print((char*)(lpFile + RvaToRaw(Rva))); cons.Print("\n");
				}
				else {
					cons.Print("0x"); cons.Print(Rva);
				}
				cons.Print("\n");
			}

		}
		cons.Print(Colors::Red);  cons.Print("\n\n================================================================\n");


		//IMPORT

	}
};