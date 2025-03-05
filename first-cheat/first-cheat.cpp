#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <memory>

#define PROCCESS_NAME "cs.exe"
#define CLIENT "client.dll"
#define HW "hw.dll"

namespace offset {
    constexpr uintptr_t on_ground_offset = 0x122E2D4;
    constexpr uintptr_t jump_offset = 0x131434;
    constexpr uintptr_t incrosshair_offset = 0x125314;
    constexpr uintptr_t m_dwPunchAngles = 0x122E324;
};
namespace utils
{
    template <typename T>
    constexpr void write_process_memory(HANDLE process, const std::uintptr_t& address, const T& value) noexcept {
        WriteProcessMemory(process, reinterpret_cast<void*>(address), &value, sizeof(T), NULL);
    }

    template <typename T>
    constexpr const T read_process_memory(HANDLE process, const std::uintptr_t& address) noexcept {
        T value = { };
        ReadProcessMemory(process, reinterpret_cast<const void*>(address), &value, sizeof(T), NULL);
        return value;
    }

     DWORD get_process_id(const char* process_name) {
        DWORD processId = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) 
        {
            PROCESSENTRY32 processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(snapshot, &processEntry)) 
            {
                do 
                {
                    if (_stricmp(processEntry.szExeFile, process_name) == 0) 
                    {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snapshot, &processEntry));
            }
	    CloseHandle(snapshot);
	}
        return processId;
    }
     uintptr_t get_module_base_address(DWORD process_id, const char* module_name) 
     {
        uintptr_t moduleBaseAddress = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(snapshot, &moduleEntry)) 
            {
                do {
                    if (_stricmp(moduleEntry.szModule, module_name) == 0) 
                    {
                        moduleBaseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                        break;
                    }
                } while (Module32Next(snapshot, &moduleEntry));
            }
            CloseHandle(snapshot);
        }
        return moduleBaseAddress;
    }
}

class processModulesBase
{
public:
    virtual ~processModulesBase() = default;
    virtual uintptr_t& getClientModuleBaseAddress() = 0;
    virtual uintptr_t& getHwModuleBaseAddress() = 0;
    virtual DWORD getProcessId() = 0;
    virtual HANDLE& getProcessHandle() = 0;
};
class cheatBase 
{
public:
    virtual void exec() = 0;
    ~cheatBase() = default;
};
class cheatManangerBase 
{
public:
    virtual void execAll() = 0;
    virtual void setAll() = 0;
    virtual ~cheatManangerBase() = default;
};
class processModules : public processModulesBase
{
public:
    processModules(const char* PROCESS_NAME, const char* CLIENT_MODULE_NAME, const char* HW_MODULE_NAME)
    {
        processId = utils::get_process_id(PROCESS_NAME);
        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        clientDll = utils::get_module_base_address(processId, CLIENT_MODULE_NAME);
        hwDll = utils::get_module_base_address(processId, HW_MODULE_NAME);
    }
    ~processModules()
    {
        if (processHandle)
            CloseHandle(processHandle);
    }
    uintptr_t& getClientModuleBaseAddress() override { return clientDll; }
    uintptr_t& getHwModuleBaseAddress() override { return hwDll; }
    DWORD getProcessId() override { return processId; }
    HANDLE& getProcessHandle() override { return processHandle; }

    inline bool isValid()
    {
        if (processId) 
        {
            if (processHandle) 
            {
                if (clientDll)
                {
                    if (hwDll)
                    {
                        return true;
                    }
                }
            }
        }
        else
            throw std::runtime_error{ "[Error, please run cs 1.6]" };      

        return false;
    };
private:
    uintptr_t clientDll = 0;
    uintptr_t hwDll = 0;
    DWORD processId = 0;
    HANDLE processHandle = nullptr;
}*objprocessModules
= new processModules(PROCCESS_NAME, CLIENT, HW);

class triggerBot : public cheatBase
{
public:
    triggerBot() {}
    void __thiscall set(const uint32_t& INCROSSHAIR_NEW) { incrosshair = INCROSSHAIR_NEW; }

    void exec() override
    {
        if (GetAsyncKeyState(0x74) && !isKeyPressed)
            isKeyPressed = true;
        else if (GetAsyncKeyState(0x74) && isKeyPressed)
            isKeyPressed = false;

        if (isKeyPressed && incrosshair == 0x02)
        {
            INPUT input = { 0 };
            input.type = INPUT_MOUSE;
            input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
            SendInput(1, &input, sizeof(INPUT));

            input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
            SendInput(1, &input, sizeof(INPUT));
        }
    }
private:
    uint32_t incrosshair = 0;
    bool isKeyPressed = false;
}*objTriggerBot 
= new triggerBot();

class bhop : public cheatBase
{
public:
    bhop(HANDLE& process, uintptr_t& client_dll) :process(process),
        client_dll(client_dll) {
    }

    void __thiscall set(const uint32_t& ON_GROUND_NEW) { on_ground = ON_GROUND_NEW; }

    void exec() override
    {
        if (GetAsyncKeyState(0x20))
        {
            on_ground ? utils::write_process_memory<int>(process, client_dll + offset::jump_offset, 5) :
                utils::write_process_memory(process, client_dll + offset::jump_offset, 4);
        }
    }
private:
    uint32_t on_ground = 0;
    HANDLE process;
    uintptr_t client_dll;
}*objBhop 
= new bhop(objprocessModules->getProcessHandle(),
                                        objprocessModules->getClientModuleBaseAddress()
                                       );
class cheatManager : public cheatManangerBase
{
public:
    cheatManager(bhop* otherObjBhop, triggerBot* otherObjTriggerBot) : objBhop(otherObjBhop),
        objTriggerBot(otherObjTriggerBot)
    {
        if (!otherObjBhop)
            otherObjBhop = nullptr;
        if (!otherObjTriggerBot)
            otherObjTriggerBot = nullptr;
    };
    ~cheatManager()
    {
        if (!objBhop)
            delete objBhop;
        if (!objTriggerBot)
            delete objTriggerBot;
    };
    void execAll() override
    {
        objBhop->exec();
        objTriggerBot->exec();
    }
    void setAll() override
    {
        objBhop->set(utils::read_process_memory<uint32_t>(
            objprocessModules->getProcessHandle(),
            objprocessModules->getHwModuleBaseAddress() + offset::on_ground_offset)
        );
        objTriggerBot->set(utils::read_process_memory<uint32_t>(
            objprocessModules->getProcessHandle(),
            objprocessModules->getClientModuleBaseAddress() + offset::incrosshair_offset)
        );
    }
private:
    bhop* objBhop = nullptr;
    triggerBot* objTriggerBot = nullptr;
}*objcheatManager 
= new cheatManager(objBhop, objTriggerBot);

bool running = true;

DWORD WINAPI readMemory(LPVOID lp)
{
    while (running)
    {
        objcheatManager->setAll();
        Sleep(5);
    }
    return 0;
}
HANDLE WINAPI startThreadReadMemory(HANDLE& process)
{
    HANDLE threadRead = CreateThread(
        NULL,
        0,
        readMemory,
        process,
        0,
        NULL
    );
    if (threadRead == NULL) {
        std::cerr << "[Error create thread!]" << std::endl;
    }
    return threadRead;
}

inline void WINAPI stopReadMemory(HANDLE& ThreadRead)
{
    if (ThreadRead) {
        running = false;
        WaitForSingleObject(ThreadRead, INFINITE);
        CloseHandle(ThreadRead);
    }
}
inline void simLoadProcess() 
{
    const char LOADING_SYMBOLS[] = { '/','-' ,'\\','|' };
    char welcomeBar[] = { "[Loading]\n*[Done]\n[Welcome!]\n[Bhop-TriggerBot] > [Active]\n[TriggerBot][off|on] > [F5]\n[Exit] > [F6]\n" };

    const int SIZE_ARRY_LOADING_SYMBOLS = sizeof(LOADING_SYMBOLS) / sizeof(LOADING_SYMBOLS[0]);
    
    for (char* i = welcomeBar; *(i) != '\0'; i++)
    {
        if(*i == '*')
        {
            for (int i = 0; i < 20; ++i)
            {
                std::cout << LOADING_SYMBOLS[i % SIZE_ARRY_LOADING_SYMBOLS] << "\r";
                std::cout.flush();
                Sleep(100);
            }
            continue;
        }
        if (*i == '>')
        {
            (*i) = 0x10;
        }
        std::cout << *i;
        Sleep(40);
    }
}

inline void stopCheat(HANDLE& threadRead, cheatManager* & objcheatManager,
                      processModules* & objprocessModules
                     )
{ 
    stopReadMemory(threadRead);
    delete objcheatManager;
    delete objprocessModules;
}
inline bool runCheat() 
{
    try
    {
        if(objprocessModules && objprocessModules->isValid())
        {
                simLoadProcess();
                HANDLE threadRead = startThreadReadMemory(objprocessModules->getProcessHandle());
                while (true) 
                {
                    if (GetAsyncKeyState(0x75)) { break;}
                    objcheatManager->execAll();
                    Sleep(1);
                }
                stopCheat(threadRead, objcheatManager, objprocessModules);
        }
    }
    catch (const std::runtime_error& error)
    {
        std::cout << error.what() << '\n';
    }
    system("pause");
    return 0;
}

int main()
{ 
    if(!runCheat()) return EXIT_SUCCESS;
}
