#include "PE_Headers.h"
#pragma comment(linker , "/HEAP:600000000")



int main() {

	ULONGLONG BigByte64;
	ULONGLONG One64 = 1;

	ULONGLONG BigByte32;
	ULONGLONG One32 = 1;

	BigByte64 = (One64 << 63);
	BigByte32 = (One32 << 63);

	unsigned char* Buffer;
	DWORD dwWritten = 0;
	DWORD FileSize = 0;

	DOS_HEADER DosHeader = {};
	PE_HEADER PeHeader = {};

	HANDLE hFile = GetHandleOfFile();

	FileSize = GetFileSize(hFile, NULL);
	Buffer = new unsigned char[FileSize];
	ReadFile(hFile, Buffer, FileSize, &dwWritten, NULL); //maximum : 512 Mb FileSize
	if (dwWritten != FileSize) {
		MessageBox(NULL, L"Error reading file", NULL, MB_OKCANCEL);
		return -1;
	}

	CloseHandle(hFile);

	std::cout << std::hex;
	Init();

	//DOS_HEADER
	CopyMemory(&DosHeader, Buffer, sizeof(IMAGE_DOS_HEADER));
	ToConsole("---------------------------------------------------\n\n", Colors::Red);
	DosHeader.print();

	//PE_HEADER
	CopyMemory(&PeHeader, &Buffer[DosHeader.e_lfanew], sizeof(PE_HEADER));
	ToConsole("\n\n---------------------------------------------------\n\n", Colors::Red);
	PeHeader.print();

	//OPTIONAL_HEADER
	ToConsole("\n\n---------------------------------------------------\n\n", Colors::Red);
	if (PeHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		OPTIONAL_HEADER32 OptionalHeader;
		CopyMemory(&OptionalHeader, &Buffer[DosHeader.e_lfanew + sizeof(PE_HEADER)], sizeof(OPTIONAL_HEADER32));
		OptionalHeader.print();

		//SECTION_HEADERS
		ToConsole("\n\n---------------------------------------------------\n\n", Colors::Red);
		ToConsole("SECTION HEADERS: \n", Colors::Green);
		SectionHeader* pSectionHeaders = (SectionHeader*) new char[sizeof(SectionHeader) * PeHeader.NumberOfSections];
		CopyMemory(pSectionHeaders, &Buffer[DosHeader.e_lfanew + sizeof(PE_HEADER) + sizeof(OptionalHeader)], sizeof(SectionHeader) * PeHeader.NumberOfSections);
		for (int i = 0; i < PeHeader.NumberOfSections; ++i) {
			pSectionHeaders[i].print();
		}
		ToConsole("---------------------------------------------------\n\n", Colors::Red);

		//IMPORT
		ToConsole("IMPORT TABLE:\n", Colors::Green);
		int ImportDescriptorStartPosition = RvaToRaw(OptionalHeader.DataDirectory[1].VirtualAddress, PeHeader.NumberOfSections, pSectionHeaders);
		IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)&Buffer[ImportDescriptorStartPosition];
		while (TRUE) {
			if (pImportDescriptor->Name == 0) break;

			DWORD RawLibName = RvaToRaw(pImportDescriptor->Name, PeHeader.NumberOfSections, pSectionHeaders);
			char* LibName = (char*)&Buffer[RawLibName];
			ToConsole("\t", Colors::Yellow); ToConsole(LibName, Colors::Yellow); ToConsole(":\n", Colors::Yellow);
			
			DWORD RawINT = RvaToRaw(pImportDescriptor->OriginalFirstThunk, PeHeader.NumberOfSections, pSectionHeaders);
			IMAGE_THUNK_DATA32* pImageThunkData32 = (IMAGE_THUNK_DATA32*)&Buffer[RawINT];
			while (TRUE) {
				if (pImageThunkData32->u1.AddressOfData == 0) break;
				if ((pImageThunkData32->u1.AddressOfData) && BigByte32) {
					ToConsole("\t\tImportByNumber: ", Colors::Blue);
					ULONGLONG Index = (pImageThunkData32->u1.AddressOfData) & (BigByte32 - 1);
					ToConsole(Index, Colors::Grey, TRUE);
					ToConsole("\n", Colors::Grey);
					pImageThunkData32++;
					continue;
				}
				DWORD RawAdressToImportByName = RvaToRaw(pImageThunkData32->u1.AddressOfData, PeHeader.NumberOfSections, pSectionHeaders);
				IMAGE_IMPORT_BY_NAME* CurrImportByName = (IMAGE_IMPORT_BY_NAME*)&Buffer[RawAdressToImportByName];
				ToConsole("\t\t", Colors::Grey); ToConsole(CurrImportByName->Name, Colors::Grey); ToConsole("\n", Colors::Grey);
				pImageThunkData32++;
			}

			ToConsole("\n\n", Colors::Yellow);
			pImportDescriptor++;
		}
		delete[] pSectionHeaders;
	}


	else {

		OPTIONAL_HEADER64 OptionalHeader;
		CopyMemory(&OptionalHeader, &Buffer[DosHeader.e_lfanew + sizeof(PE_HEADER)], sizeof(OPTIONAL_HEADER64));
		OptionalHeader.print();

		//SECTION_HEADERS
		ToConsole("\n\n---------------------------------------------------\n\n", Colors::Red);
		ToConsole("SECTION HEADERS: \n\n", Colors::Green);
		SectionHeader* pSectionHeaders = (SectionHeader*) new char[sizeof(SectionHeader) * PeHeader.NumberOfSections];
		CopyMemory(pSectionHeaders, &Buffer[DosHeader.e_lfanew + sizeof(PE_HEADER) + sizeof(OptionalHeader)], sizeof(SectionHeader) * PeHeader.NumberOfSections);
		for (int i = 0; i < PeHeader.NumberOfSections; ++i) {
			pSectionHeaders[i].print();
		}
		ToConsole("---------------------------------------------------\n\n", Colors::Red);

		//IMPORT
		ToConsole("IMPORT TABLE:\n", Colors::Green);
		int ImportDescriptorStartPosition = RvaToRaw(OptionalHeader.DataDirectory[1].VirtualAddress, PeHeader.NumberOfSections, pSectionHeaders);
		IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)&Buffer[ImportDescriptorStartPosition];
		while (TRUE) {
			if (pImportDescriptor->Name == 0) break;

			DWORD RawLibName = RvaToRaw(pImportDescriptor->Name, PeHeader.NumberOfSections, pSectionHeaders);
			char* LibName = (char*)&Buffer[RawLibName];
			ToConsole("\t", Colors::Yellow); ToConsole(LibName, Colors::Yellow); ToConsole(":\n", Colors::Yellow);


			DWORD RawINT = RvaToRaw(pImportDescriptor->OriginalFirstThunk, PeHeader.NumberOfSections, pSectionHeaders);
			IMAGE_THUNK_DATA64* pImageThunkData64 = (IMAGE_THUNK_DATA64*)&Buffer[RawINT];
			while (TRUE) {
				if (pImageThunkData64->u1.AddressOfData == 0) break;
				if (((pImageThunkData64->u1.AddressOfData) & BigByte64) != 0 ) {
					ToConsole("\t\tImportByNumber: ", Colors::Blue);
					ULONGLONG Index = (pImageThunkData64->u1.AddressOfData) & (BigByte64 - 1);
					ToConsole(Index, Colors::Grey, TRUE); 
					ToConsole("\n", Colors::Grey);
					pImageThunkData64++;
					continue;
				}
				DWORD RawAdressToImportByName = RvaToRaw(pImageThunkData64->u1.AddressOfData, PeHeader.NumberOfSections, pSectionHeaders);
				IMAGE_IMPORT_BY_NAME* CurrImportByName = (IMAGE_IMPORT_BY_NAME*)&Buffer[RawAdressToImportByName];
				ToConsole("\t\t", Colors::Grey); ToConsole(CurrImportByName->Name, Colors::Grey); ToConsole("\n", Colors::Grey);
				pImageThunkData64++;
			}

			ToConsole("\n\n", Colors::Yellow);
			pImportDescriptor++;
		}
		delete[] pSectionHeaders;
	}

	delete[] Buffer;
	return 0;
}