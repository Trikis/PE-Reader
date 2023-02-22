#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <string>
#include <iostream>
#include <map>


#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)


enum Colors {
	Black = 0,
	Red = FOREGROUND_RED,
	Green = FOREGROUND_GREEN,
	Yellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	Blue = FOREGROUND_BLUE,
	Grey = FOREGROUND_INTENSITY , 
};

HANDLE hStdOutput;
CONSOLE_SCREEN_BUFFER_INFO ScreenBufferInfo;
WORD wOldCololorAttributes;


DWORD gFileAlignment;
DWORD gSectionAlignment;
std::map<int, std::string> TypeCharacteristics = {
	{0x8 , "IMAGE_SCN_TYPE_NO_PAD "} ,
	{0x20 , "IMAGE_SCN_CNT_CODE "} ,
	{0x40 , "IMAGE_SCN_CNT_INITIALIZED_DATA "} ,
	{0x80 , "IMAGE_SCN_CNT_UNINITIALIZED_DATA "} ,
	{0x200 , "IMAGE_SCN_LNK_INFO "} ,
	{0x800 , "IMAGE_SCN_LNK_REMOVE "} ,
	{0x1000 , "IMAGE_SCN_LNK_COMDAT "} ,
	{0x4000 , "IMAGE_SCN_NO_DEFER_SPEC_EXC "} ,
	{0x8000 , "IMAGE_SCN_GPREL "} ,
	{0x100000 , "IMAGE_SCN_ALIGN_1BYTES "} ,
	{0x200000 , "IMAGE_SCN_ALIGN_2BYTES "} ,
	{0x300000 , "IMAGE_SCN_ALIGN_4BYTES "} ,
	{0x400000 , "IMAGE_SCN_ALIGN_8BYTES "} ,
	{0x500000 , "IMAGE_SCN_ALIGN_16BYTES "} ,
	{0x600000 , "IMAGE_SCN_ALIGN_32BYTES "} ,
	{0x700000 , "IMAGE_SCN_ALIGN_64BYTES "} ,
	{0x800000 , "IMAGE_SCN_ALIGN_128BYTES "} ,
	{0x900000 , "IMAGE_SCN_ALIGN_256BYTES "} ,
	{0xa00000 , "IMAGE_SCN_ALIGN_512BYTES "} ,
	{0xb00000 , "IMAGE_SCN_ALIGN_1024BYTES "} ,
	{0xc00000 , "IMAGE_SCN_ALIGN_2048BYTES "} ,
	{0xd00000 , "IMAGE_SCN_ALIGN_4096BYTES "} ,
	{0xe00000 , "IMAGE_SCN_ALIGN_8192BYTES "} ,
	{0x1000000 , "IMAGE_SCN_LINK_NRELOC_OVFL "} ,
	{0x2000000 , "IMAGE_SCN_MEM_DISCARDABLE "} ,
	{0x4000000 , "IMAGE_SCN_MEM_NOT_CACHED "} ,
	{0x8000000 , "IMAGE_SCN_MEM_NOT_PAGED "} ,
	{0x10000000 , "IMAGE_SCN_MEM_SHARED "} ,
	{0x20000000 , "IMAGE_SCN_MEM_EXECUTE "} ,
	{0x40000000 , "IMAGE_SCN_MEM_READ "} ,
	{0x80000000 , "IMAGE_SCN_MEM_WRITE"}
};

void Init() {
	hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hStdOutput, &ScreenBufferInfo);
	wOldCololorAttributes = ScreenBufferInfo.wAttributes;

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

template<typename T>void  ToConsole(T t, WORD ColorAttributes, bool Format = FALSE) {
	SetConsoleTextAttribute(hStdOutput, ColorAttributes);
	if (Format) std::cout << "0x";
	std::cout << t;
}

HANDLE GetHandleOfFile() {
	OPENFILENAME ofn;
	wchar_t szFile[256];
	HANDLE retHandle;

	ZeroMemory(szFile, sizeof(szFile));
	ZeroMemory(&ofn, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"All\0*.exe;*.dll\0\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!GetOpenFileNameW(&ofn)) {
		MessageBox(NULL, L"Error Occupation", 0, 0);
		ExitProcess(CommDlgExtendedError());
	}

	retHandle = CreateFile(ofn.lpstrFile, GENERIC_READ,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (retHandle == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, L"Error Occupation", NULL, MB_OKCANCEL);
		ExitProcess(-1);
	}
	return retHandle;
}


class DOS_HEADER : public IMAGE_DOS_HEADER {
public:
	DOS_HEADER() : IMAGE_DOS_HEADER() {}

	void print() {
		ToConsole("DOS HEADER: \n", Colors::Green);
		ToConsole("\te_magic: ", Colors::Yellow);
		if (e_magic != 0x5a4d) {
			ToConsole(e_magic, Colors::Grey, TRUE);
			ToConsole(" INCCORECT FILE TYPE", Colors::Red);
			ExitProcess(-1);
		}
		ToConsole("MZ\n", Colors::Grey);
		ToConsole("\te_cblp: ", Colors::Yellow); ToConsole(e_cblp, Colors::Grey, TRUE);
		ToConsole("\n\te_cp: ", Colors::Yellow); ToConsole(e_cp, Colors::Grey, TRUE);
		ToConsole("\n\te_crlc: ", Colors::Yellow); ToConsole(e_crlc, Colors::Grey, TRUE);
		ToConsole("\n\te_cparhdr: ", Colors::Yellow); ToConsole(e_cparhdr, Colors::Grey, TRUE);
		ToConsole("\n\te_minalloc: ", Colors::Yellow); ToConsole(e_minalloc, Colors::Grey, TRUE);
		ToConsole("\n\te_maxalloc: ", Colors::Yellow); ToConsole(e_maxalloc, Colors::Grey, TRUE);
		ToConsole("\n\te_ss: ", Colors::Yellow); ToConsole(e_ss, Colors::Grey, TRUE);
		ToConsole("\n\te_sp: ", Colors::Yellow); ToConsole(e_sp, Colors::Grey, TRUE);
		ToConsole("\n\te_csum: ", Colors::Yellow); ToConsole(e_csum, Colors::Grey, TRUE);
		ToConsole("\n\te_ip: ", Colors::Yellow); ToConsole(e_ip, Colors::Grey, TRUE);
		ToConsole("\n\te_cs: ", Colors::Yellow); ToConsole(e_cs, Colors::Grey, TRUE);
		ToConsole("\n\te_lfarlc: ", Colors::Yellow); ToConsole(e_lfarlc, Colors::Grey, TRUE);
		ToConsole("\n\te_ovno: ", Colors::Yellow); ToConsole(e_ovno, Colors::Grey, TRUE);
		ToConsole("\n\te_oemid: ", Colors::Yellow); ToConsole(e_oemid, Colors::Grey, TRUE);
		ToConsole("\n\te_oeminfo: ", Colors::Yellow); ToConsole(e_oeminfo, Colors::Grey, TRUE);
		ToConsole("\n\te_lfanew: ", Colors::Yellow); ToConsole(e_lfanew, Colors::Grey, TRUE);
	}
};

class PE_HEADER{
public:
	DWORD Signature;
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;

	static std::string TimeDateStampToString(DWORD TimeDateStamp) {
		std::string res = "";
		char* Arr;
		Arr = ctime((const time_t*)&TimeDateStamp);
		for (int i = 0; i < 26; ++i) {
			res += Arr[i];
		}
		return res;
	}

	void print() {
		ToConsole("PE HEADER:\n", Colors::Green);
		ToConsole("\tSignature: ", Colors::Yellow);
		if (Signature != 0x4550) {
			ToConsole(Signature, Colors::Grey, TRUE);
			ToConsole(" INCCORECT FILE TYPE", Colors::Red);
			ExitProcess(-1);
		}
		ToConsole("PE", Colors::Grey);
		ToConsole("\n\tMachine: ", Colors::Yellow);
		switch (Machine) {
		case IMAGE_FILE_MACHINE_I386:
		{
			ToConsole("IMAGE_FILE_MACHINE_I386\n", Colors::Grey);
			break;
		}
		case IMAGE_FILE_MACHINE_IA64:
		{
			ToConsole("IMAGE_FILE_MACHINE_IA64\n", Colors::Grey);
			break;
		}
		case IMAGE_FILE_MACHINE_AMD64:
		{
			ToConsole("IMAGE_FILE_MACHINE_AMD64\n", Colors::Grey);
			break;
		}
		default:
		{
			ToConsole(Machine, Colors::Grey, TRUE);
			ToConsole(" INCORRECT FILE TYPE", Colors::Red);
			ExitProcess(-1);
		}
		}
		ToConsole("\tNumberOfSections: ", Colors::Yellow); ToConsole(NumberOfSections, Colors::Grey, TRUE);
		ToConsole("\n\tTimeDateStamp: ", Colors::Yellow);  ToConsole(TimeDateStamp, Colors::Grey);
		ToConsole("\n\tPointerToSymbolTable: ", Colors::Yellow); ToConsole(PointerToSymbolTable, Colors::Grey, TRUE);
		ToConsole("\n\tNumberOfSymbols: ", Colors::Yellow); ToConsole(NumberOfSymbols, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfOptionalHeader: ", Colors::Yellow); ToConsole(SizeOfOptionalHeader, Colors::Grey, TRUE);
		ToConsole("\n\tCharacteristics: ", Colors::Yellow);
		if ((Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == IMAGE_FILE_RELOCS_STRIPPED) ToConsole("IMAGE_FILE_RELOCS_STRIPPED ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE) ToConsole("IMAGE_FILE_EXECUTABLE_IMAGE ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) == IMAGE_FILE_LINE_NUMS_STRIPPED) ToConsole("IMAGE_FILE_LINE_NUMS_STRIPPED ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) == IMAGE_FILE_LOCAL_SYMS_STRIPPED) ToConsole("IMAGE_FILE_LOCAL_SYMS_STRIPPED ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) == IMAGE_FILE_AGGRESIVE_WS_TRIM) ToConsole("IMAGE_FILE_AGGRESIVE_WS_TRIM ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE) ToConsole("IMAGE_FILE_LARGE_ADDRESS_AWARE ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) == IMAGE_FILE_BYTES_REVERSED_LO) ToConsole("IMAGE_FILE_BYTES_REVERSED_LO ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE) ToConsole("IMAGE_FILE_32BIT_MACHINE ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_DEBUG_STRIPPED) == IMAGE_FILE_DEBUG_STRIPPED) ToConsole("IMAGE_FILE_DEBUG_STRIPPED ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) == IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) ToConsole("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) == IMAGE_FILE_NET_RUN_FROM_SWAP) ToConsole("IMAGE_FILE_NET_RUN_FROM_SWAP ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_SYSTEM) == IMAGE_FILE_SYSTEM) ToConsole("IMAGE_FILE_SYSTEM ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) ToConsole("IMAGE_FILE_DLL ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) == IMAGE_FILE_UP_SYSTEM_ONLY) ToConsole("IMAGE_FILE_UP_SYSTEM_ONLY ", Colors::Grey);
		if ((Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) == IMAGE_FILE_BYTES_REVERSED_HI) ToConsole("IMAGE_FILE_BYTES_REVERSED_HI ", Colors::Grey);

	}
};

class OPTIONAL_HEADER32 : public IMAGE_OPTIONAL_HEADER32 {
public:
	void print() {
		gFileAlignment = this->FileAlignment;
		gSectionAlignment = this->SectionAlignment;
		ToConsole("OPTIONAL_HEADER : \n", Colors::Green);
		ToConsole("\tMagic: ", Colors::Yellow);
		switch (Magic) {
			case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			{
				ToConsole("PE32\n", Colors::Grey);
				break;
			}
			case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			{
				ToConsole("PE32+\n", Colors::Grey); //This is not error
				break;
			}
			case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
			{
				ToConsole("ROM device\n", Colors::Grey);
				break;
			}
			default:
			{
				ToConsole("Error occupation\n", Colors::Red);
				ExitProcess(-1);
			}
		}
		std::cout << std::dec;
		ToConsole("\tLinkerVersion: ", Colors::Yellow); ToConsole((int)MajorLinkerVersion, Colors::Grey); ToConsole(".", Colors::Grey);  ToConsole((int)MinorLinkerVersion, Colors::Grey);
		std::cout << std::hex;
		ToConsole("\n\tSizeOfCode: ", Colors::Yellow); ToConsole(SizeOfCode, Colors::Grey , TRUE);
		ToConsole("\n\tSizeOfInitializedData: ", Colors::Yellow); ToConsole(SizeOfInitializedData, Colors::Grey , TRUE);
		ToConsole("\n\tSizeOfUninitializedData: ", Colors::Yellow); ToConsole(SizeOfUninitializedData, Colors::Grey , TRUE);
		ToConsole("\n\tAddressOfEntryPoint: ", Colors::Yellow); ToConsole(AddressOfEntryPoint, Colors::Grey, TRUE);
		ToConsole("\n\tBaseOfCode: ", Colors::Yellow); ToConsole(BaseOfCode, Colors::Grey, TRUE);
		ToConsole("\n\tBaseOfData: ", Colors::Yellow); ToConsole(BaseOfData, Colors::Grey, TRUE);
		ToConsole("\n\tImageBase: ", Colors::Yellow); ToConsole(ImageBase, Colors::Grey, TRUE);
		ToConsole("\n\tSectionAlignment: ", Colors::Yellow); ToConsole(SectionAlignment, Colors::Grey, TRUE);
		ToConsole("\n\tFileAlignment: ", Colors::Yellow); ToConsole(FileAlignment, Colors::Grey, TRUE);
		std::cout << std::dec;
		ToConsole("\n\tOperatingSystemVersion: ", Colors::Yellow); ToConsole((int)MajorOperatingSystemVersion, Colors::Grey); ToConsole(".", Colors::Grey); ToConsole((int)MinorOperatingSystemVersion, Colors::Grey);
		ToConsole("\n\tImageVersion: ", Colors::Yellow); ToConsole((int)MajorImageVersion, Colors::Grey); ToConsole(".", Colors::Grey); ToConsole((int)MinorImageVersion, Colors::Grey);
		ToConsole("\n\tSubsystemVersion: ", Colors::Yellow); ToConsole((int)MajorSubsystemVersion, Colors::Grey); ToConsole(".", Colors::Grey); ToConsole((int)MinorSubsystemVersion, Colors::Grey);
		std::cout << std::hex;
		ToConsole("\n\tWin32VersionValue: ", Colors::Yellow); ToConsole(Win32VersionValue , Colors::Grey);
		ToConsole("\n\tSizeOfImage: " , Colors::Yellow);
		if (SizeOfImage % SectionAlignment != 0) {
			ToConsole(SizeOfImage, Colors::Grey); ToConsole(" INCORRECT VALUE", Colors::Red);
			ExitProcess(-1);
		}
		ToConsole(SizeOfImage, Colors::Grey , TRUE);
		ToConsole("\n\tSizeOfHeaders: ", Colors::Yellow); ToConsole(SizeOfHeaders, Colors::Grey , TRUE);
		ToConsole("\n\tCheckSum: ", Colors::Yellow); ToConsole(CheckSum, Colors::Grey , TRUE);
		ToConsole("\n\tSubsytem: ", Colors::Yellow);
		switch (Subsystem) {
			case IMAGE_SUBSYSTEM_UNKNOWN:
			{
				ToConsole("IMAGE_SUBSYSTEM_UNKNOWN", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_NATIVE:
			{
				ToConsole("IMAGE_SUBSYSTEM_NATIVE", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_GUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_CUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_OS2_CUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_OS2_CUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_POSIX_CUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_POSIX_CUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_APPLICATION", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_ROM:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_ROM", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_XBOX:
			{
				ToConsole("IMAGE_SUBSYSTEM_XBOX", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", Colors::Grey);
				break;
			}
		}
		ToConsole("\n\tDllCharacteristics: ", Colors::Yellow);
		if ((DllCharacteristics & 0x20) == 0x20) ToConsole("IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA ", Colors::Grey);
		if ((DllCharacteristics & 0x40) == 0x40) ToConsole("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ", Colors::Grey);
		if ((DllCharacteristics & 0x80) == 0x80) ToConsole("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ", Colors::Grey);
		if ((DllCharacteristics & 0x100) == 0x100) ToConsole("IMAGE_DLLCHARACTERISTICS_NX_COMPAT ", Colors::Grey);
		if ((DllCharacteristics & 0x200) == 0x200) ToConsole("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ", Colors::Grey);
		if ((DllCharacteristics & 0x400) == 0x400) ToConsole("IMAGE_DLLCHARACTERISTICS_NO_SEH ", Colors::Grey);
		if ((DllCharacteristics & 0x800) == 0x800) ToConsole("IMAGE_DLLCHARACTERISTICS_NO_BIND ", Colors::Grey);
		if ((DllCharacteristics & 0x1000) == 0x1000) ToConsole("IMAGE_DLL_CHARACTERISTICS_APPCONTAINER ", Colors::Grey);
		if ((DllCharacteristics & 0x2000) == 0x2000) ToConsole("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ", Colors::Grey);
		if ((DllCharacteristics & 0x4000) == 0x4000) ToConsole("IMAGE_DLL_CHARACTERISTICS_GUARD_CF ", Colors::Grey);
		if ((DllCharacteristics & 0x8000) == 0x8000) ToConsole("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ", Colors::Grey);

		ToConsole("\n\tSizeOfStackReserve: ", Colors::Yellow); ToConsole(SizeOfStackReserve, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfStackCommit: ", Colors::Yellow); ToConsole(SizeOfStackCommit, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfHeapReserve: ", Colors::Yellow); ToConsole(SizeOfHeapReserve, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfHeapCommit: ", Colors::Yellow); ToConsole(SizeOfHeapCommit, Colors::Grey, TRUE);
		ToConsole("\n\tLoaderFlags: ", Colors::Yellow); ToConsole(LoaderFlags, Colors::Grey, TRUE);
		ToConsole("\n\tNumberOfRvaAndSizes: ", Colors::Yellow); ToConsole(NumberOfRvaAndSizes, Colors::Grey, TRUE);
	}
};

class OPTIONAL_HEADER64 : public IMAGE_OPTIONAL_HEADER64 {
public:
	void print() {
		gFileAlignment = this->FileAlignment;
		gSectionAlignment = this->SectionAlignment;
		ToConsole("OPTIONAL_HEADER : \n", Colors::Green);
		ToConsole("\tMagic: ", Colors::Yellow);
		switch (Magic) {
			case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			{
				ToConsole("PE32\n", Colors::Grey);
				break;
			}
			case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			{
				ToConsole("PE32+\n", Colors::Grey); //This is not error
				break;
			}
			case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
			{
				ToConsole("ROM device\n", Colors::Grey);
				break;
			}
			default:
			{
				ToConsole("Error occupation\n", Colors::Red);
				ExitProcess(-1);
			}
		}
		std::cout << std::dec;
		ToConsole("\tLinkerVersion: ", Colors::Yellow); ToConsole((int)MajorLinkerVersion, Colors::Grey); ToConsole(".", Colors::Grey);  ToConsole((int)MinorLinkerVersion, Colors::Grey);
		std::cout << std::hex;
		ToConsole("\n\tSizeOfCode: ", Colors::Yellow); ToConsole(SizeOfCode, Colors::Grey , TRUE);
		ToConsole("\n\tSizeOfInitializedData: ", Colors::Yellow); ToConsole(SizeOfInitializedData, Colors::Grey , TRUE);
		ToConsole("\n\tSizeOfUninitializedData: ", Colors::Yellow); ToConsole(SizeOfUninitializedData, Colors::Grey , TRUE);
		ToConsole("\n\tAddressOfEntryPoint: ", Colors::Yellow); ToConsole(AddressOfEntryPoint, Colors::Grey, TRUE);
		ToConsole("\n\tBaseOfCode: ", Colors::Yellow); ToConsole(BaseOfCode, Colors::Grey, TRUE);
		ToConsole("\n\tImageBase: ", Colors::Yellow); ToConsole(ImageBase, Colors::Grey, TRUE);
		ToConsole("\n\tSectionAlignment: ", Colors::Yellow); ToConsole(SectionAlignment, Colors::Grey, TRUE);
		ToConsole("\n\tFileAlignment: ", Colors::Yellow); ToConsole(FileAlignment, Colors::Grey, TRUE);
		std::cout << std::dec;
		ToConsole("\n\tOperatingSystemVersion: ", Colors::Yellow); ToConsole((int)MajorOperatingSystemVersion, Colors::Grey); ToConsole(".", Colors::Grey); ToConsole((int)MinorOperatingSystemVersion, Colors::Grey);
		ToConsole("\n\tImageVersion: ", Colors::Yellow); ToConsole((int)MajorImageVersion, Colors::Grey); ToConsole(".", Colors::Grey); ToConsole((int)MinorImageVersion, Colors::Grey);
		ToConsole("\n\tSubsystemVersion: ", Colors::Yellow); ToConsole((int)MajorSubsystemVersion, Colors::Grey); ToConsole(".", Colors::Grey); ToConsole((int)MinorSubsystemVersion, Colors::Grey);
		std::cout << std::hex;
		ToConsole("\n\tWin32VersionValue: ", Colors::Yellow); ToConsole(Win32VersionValue, Colors::Grey);
		ToConsole("\n\tSizeOfImage: ", Colors::Yellow );
		if (SizeOfImage % SectionAlignment != 0) {
			ToConsole(SizeOfImage, Colors::Grey , TRUE); ToConsole(" INCORRECT VALUE", Colors::Red);
			ExitProcess(-1);
		}
		ToConsole(SizeOfImage, Colors::Grey , TRUE);
		ToConsole("\n\tSizeOfHeaders: ", Colors::Yellow); ToConsole(SizeOfHeaders, Colors::Grey , TRUE);
		ToConsole("\n\tCheckSum: ", Colors::Yellow); ToConsole(CheckSum, Colors::Grey , TRUE);
		ToConsole("\n\tSubsytem: ", Colors::Yellow);
		switch (Subsystem) {
			case IMAGE_SUBSYSTEM_UNKNOWN:
			{
				ToConsole("IMAGE_SUBSYSTEM_UNKNOWN", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_NATIVE:
			{
				ToConsole("IMAGE_SUBSYSTEM_NATIVE", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_GUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_CUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_OS2_CUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_OS2_CUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_POSIX_CUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_POSIX_CUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_APPLICATION", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_EFI_ROM:
			{
				ToConsole("IMAGE_SUBSYSTEM_EFI_ROM", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_XBOX:
			{
				ToConsole("IMAGE_SUBSYSTEM_XBOX", Colors::Grey);
				break;
			}
			case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			{
				ToConsole("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", Colors::Grey);
				break;
			}
		}
		ToConsole("\n\tDllCharacteristics: ", Colors::Yellow);
		if ((DllCharacteristics & 0x40) == 0x40) ToConsole("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ", Colors::Grey);
		if ((DllCharacteristics & 0x80) == 0x80) ToConsole("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ", Colors::Grey);
		if ((DllCharacteristics & 0x100) == 0x100) ToConsole("IMAGE_DLLCHARACTERISTICS_NX_COMPAT ", Colors::Grey);
		if ((DllCharacteristics & 0x200) == 0x200) ToConsole("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ", Colors::Grey);
		if ((DllCharacteristics & 0x400) == 0x400) ToConsole("IMAGE_DLLCHARACTERISTICS_NO_SEH ", Colors::Grey);
		if ((DllCharacteristics & 0x800) == 0x800) ToConsole("IMAGE_DLLCHARACTERISTICS_NO_BIND ", Colors::Grey);
		if ((DllCharacteristics & 0x2000) == 0x2000) ToConsole("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ", Colors::Grey);
		if ((DllCharacteristics & 0x8000) == 0x8000) ToConsole("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ", Colors::Grey);

		ToConsole("\n\tSizeOfStackReserve: ", Colors::Yellow); ToConsole(SizeOfStackReserve, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfStackCommit: ", Colors::Yellow); ToConsole(SizeOfStackCommit, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfHeapReserve: ", Colors::Yellow); ToConsole(SizeOfHeapReserve, Colors::Grey, TRUE);
		ToConsole("\n\tSizeOfHeapCommit: ", Colors::Yellow); ToConsole(SizeOfHeapCommit, Colors::Grey, TRUE);
		ToConsole("\n\tLoaderFlags: ", Colors::Yellow); ToConsole(LoaderFlags, Colors::Grey, TRUE);
		ToConsole("\n\tNumberOfRvaAndSizes: ", Colors::Yellow); ToConsole(NumberOfRvaAndSizes, Colors::Grey, TRUE);
	}
};

class SectionHeader : public IMAGE_SECTION_HEADER {
public:
	void print() {
		ToConsole("\t", 7); ToConsole(Name, 7); ToConsole(":\n", 7);
		ToConsole("\t\tVirtualSize: ", Colors::Yellow); ToConsole(Misc.VirtualSize, Colors::Grey, TRUE);
		ToConsole("\n\t\tVirtualAddress: ", Colors::Yellow); ToConsole(VirtualAddress, Colors::Grey, TRUE);
		ToConsole("\n\t\tSizeOfRawData: ", Colors::Yellow);  ToConsole(SizeOfRawData, Colors::Grey, TRUE);
		if (SizeOfRawData % gFileAlignment != 0) {
			ToConsole(" Error Occupation\n", Colors::Red);
			ExitProcess(-1);
		}
		ToConsole("\n\t\tPointerToRawData: ", Colors::Yellow); ToConsole(PointerToRawData, Colors::Grey, TRUE);
		if (PointerToRawData % gFileAlignment != 0) {
			ToConsole(" Error occupation\n", Colors::Red);
			ExitProcess(-1);
		}
		ToConsole("\n\t\tPointerToRelocations: ", Colors::Yellow); ToConsole(PointerToRelocations, Colors::Grey, TRUE);
		ToConsole("\n\t\tPointerToLinenumbers: ", Colors::Yellow); ToConsole(PointerToLinenumbers, Colors::Grey, TRUE);
		ToConsole("\n\t\tNumberOfRelocations: ", Colors::Yellow); ToConsole(NumberOfRelocations, Colors::Grey, TRUE);
		ToConsole("\n\t\tNumberOfLinenumbers: ", Colors::Yellow); ToConsole(NumberOfLinenumbers, Colors::Grey, TRUE);
		ToConsole("\n\t\tCharacteristics: " , Colors::Yellow);

		for (std::map<int, std::string>::iterator iter = TypeCharacteristics.begin(); iter != TypeCharacteristics.end(); ++iter) {
			int Code = iter->first;
			std::string Description = iter->second;
			if ((Characteristics & Code) == Code) ToConsole(Description, Colors::Grey);
		}

		ToConsole("\n\n", 7);
	}
};

int defSection(ULONGLONG RVA, WORD NumberOfSections, SectionHeader* pSectionHeader) {
	for (int i = 0; i < NumberOfSections; ++i) {
		DWORD start = pSectionHeader[i].VirtualAddress;
		DWORD end = start + ALIGN_UP(pSectionHeader[i].Misc.VirtualSize, gSectionAlignment) - 1;
		if (RVA >= start && RVA <= end) return i;
	}
	return -1;
}

int RvaToRaw(ULONGLONG RVA, WORD NumberOfSections, SectionHeader* pSectionHeader) {
	int indexSection = defSection(RVA, NumberOfSections, pSectionHeader);
	if (indexSection == -1) {
		MessageBox(NULL, L"Error Occupation", NULL, MB_OKCANCEL);
		ExitProcess(-1);
	}
	return RVA - pSectionHeader[indexSection].VirtualAddress + pSectionHeader[indexSection].PointerToRawData;
}