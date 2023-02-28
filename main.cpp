#include "Pe-Reader.h"

int main() {
	MappedFile mf;
	LPBYTE lpFile = mf.getViewOfFile();
	try {
		PeParser peParser(lpFile);
		peParser.print();
	}
	catch (const std::exception& Exception) {
		MessageBoxA(NULL, Exception.what(), NULL, MB_OKCANCEL);
		return GetLastError();
	}
	return 0;
}