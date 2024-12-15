#include <iostream>
#include <string>
#include <sstream>
#include <windows.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_GRAY    "\033[90m"

std::string regkey = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VRChat.exe\\PerfOptions";

void printAppInfo() {
    SetConsoleTitle(TEXT("VRChat Priority Setter"));

    std::cout << COLOR_BOLD << COLOR_MAGENTA << "   _   _   _   _   _   _     _   _   _   _     _   _   _   _   _   _  \n"
        "  / \\ / \\ / \\ / \\ / \\ / \\   / \\ / \\ / \\ / \\   / \\ / \\ / \\ / \\ / \\ / \\ \n"
        " ( V | R | C | H | A | T ) ( P | R | I | O ) ( S | E | T | T | E | R ) ~by Aggi\n"
        "  \\_/ \\_/ \\_/ \\_/ \\_/ \\_/   \\_/ \\_/ \\_/ \\_/   \\_/ \\_/ \\_/ \\_/ \\_/ \\_/ \n" << COLOR_RESET;
    std::cout << COLOR_BOLD << COLOR_GRAY << "-----------------------------------------------------------------------------------------------------\n\n\n" << COLOR_RESET;
    
    std::cout << COLOR_GRAY << "[ i ] Information | EasyAntiCheat prevents you from setting the priority of VRChat.\n";
    std::cout << "[ i ] Information | This script allows you to set the priority of VRChat on startup, bypassing this restriction. \n";
    std::cout << "[ i ] Information | No, it's not bannable and won't change any settings, it just adds one REG KEY:\n";
    std::cout << COLOR_BOLD << COLOR_GRAY << "-----------------------------------------------------------------------------------------------------\n" << COLOR_RESET;
    std::cout << "[ ~ ] Loading | Grabbing the REG KEY....\n" << COLOR_RESET;
    std::cout << "[ # ] Debug | " << regkey << "\n" << COLOR_RESET;
    std::cout << COLOR_BOLD << COLOR_GRAY << "-----------------------------------------------------------------------------------------------------\n" << COLOR_RESET;
    Sleep(1000);
    std::cout << COLOR_BOLD << COLOR_RED << "----------------------------------------------------------------------------------------------------\n" << COLOR_RESET;
    std::cout << COLOR_RED << "[ i ] Note: Realtime priority is Possible but not Recomended :(. As it might conflickt with the Operating System.\n" << COLOR_RESET;
    std::cout << COLOR_RED << "[ i ] Note: Made by me (AG7/Maggi | NotAG7 | literally.ag7).\n[ i ] FREE & OPEN SOURCE!!! IF YOU PAID FOR IT YOU GOT SCAMMED :(\n" << COLOR_RESET;
    std::cout << COLOR_BOLD << COLOR_RED << "----------------------------------------------------------------------------------------------------\n" << COLOR_RESET;

    std::cout << COLOR_WHITE << "[ i ] Priority Options : \n\n" << COLOR_RESET;
    std::cout << COLOR_GREEN << "[ > ] 2: Normal (standard)\n" << COLOR_RESET;
    std::cout << COLOR_CYAN << "[ > ] 3: High (recommended)\n" << COLOR_RESET;
    std::cout << COLOR_GRAY << "[ > ] 5: Below Normal\n" << COLOR_RESET;
    std::cout << COLOR_GRAY << "[ > ] 6: Above Normal\n\n" << COLOR_RESET;




}

bool IsRunningAsAdmin()
{
    BOOL fIsRunningAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        return false;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunningAsAdmin))
    {
        fIsRunningAsAdmin = FALSE;
    }


    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
    }

    return fIsRunningAsAdmin == TRUE;
}

void RestartAsAdmin()
{
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
    {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei))
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED)
            {
                std::wcout << COLOR_RED << L"[ ! ] Critical | User refused to allow elevation. Terminating!" << std::endl;
                Sleep(3000);
                ExitProcess(0);
            }
        }
        else
        {
            ExitProcess(0);
        }
    }
}

int checkadmin() {
    if (IsRunningAsAdmin())
    {
        std::cout << COLOR_GREEN << "[ & ] Configuration | The program is running as administrator." << std::endl;
    }
    else
    {
        std::cout << COLOR_RED << "[ ! ] Critical! | The program is not running as administrator. Restarting as administrator..." << std::endl;
        Sleep(3000);
        RestartAsAdmin();
    }

    return 0;
}


int PriorityInput() {
    std::string input;
    int priority;

    std::cout << COLOR_MAGENTA << "[ ? ] Input Required (2-6): " << COLOR_RESET;
    std::getline(std::cin, input);

    std::stringstream strstream(input);
    strstream >> priority;

    if (strstream.fail()) {
        std::cerr << COLOR_RED << "[ - ] Failure | Error: Invalid input. Please enter a valid number.\n\n" << COLOR_RESET;
        return PriorityInput(); 
    }

    if (priority < 2 || priority > 6) {
        std::cerr << COLOR_RED << "[ - ] Failure | Error: Invalid priority level. Please enter a number between 2 and 6.\n\n" << COLOR_RESET;
        return PriorityInput(); 
    }

    return priority;
}


void setPriority(int priority) {
    std::string cmd("REG ADD \"" + regkey + "\" /f /v \"CpuPriorityClass\" /t REG_DWORD /d ");
    cmd += std::to_string(priority);
    cmd += " >nul";

    system(cmd.c_str());
    std::cout << "\n" << COLOR_YELLOW << "[ ~ ] Initializing.....\n" << COLOR_RESET;
    Sleep(1000);
    std::cout << "\n" << COLOR_YELLOW << "[ * ] Processing.....\n" << COLOR_RESET;
    Sleep(1000);
    std::cout << "\n" << COLOR_YELLOW << "[ * ] Executing.....\n" << COLOR_RESET;
    Sleep(1000);
    std::cout << "\n" << COLOR_GREEN << "[ + ] Success ! Priority of VRChat has been set to: " << priority << "\n\n" << COLOR_RESET;
    Sleep(3000);
}

int main() {
    system("cls");
    checkadmin();
    system("cls");
    printAppInfo();
    int priority = PriorityInput();
    setPriority(priority);
    main();
}

