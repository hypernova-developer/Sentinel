#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <fstream>
#include <bcrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

struct ThreatInfo {
    int Score;
    std::vector<std::string> Reasons;
};

std::string version = "2.0.0-LTS";
std::string quarantineDir = "C:\\Tools\\Jenny\\Quarantine";
std::string currentSelfHash = "";
std::map<std::string, ThreatInfo> detectedThreats;

std::vector<std::string> criticalServices = {
    "wpcmonsvc", "svchost", "lsass", "services", "wininit",
    "csrss", "smss", "winlogon", "taskhostw", "spoolsv"
};

std::vector<std::string> developerWorkspaces = {
    "D:\\Tools", "D:\\mingw64", "C:\\msys64", "D:\\Developing"
};

std::vector<std::string> driverWhitelist = {
    "pusat k3", "hid.exe", "mouseconfig", "keyboard driver", "peripheral"
};

std::string GetFileHash(std::string filename);
bool IsFileSigned(std::string path);
bool IsHardwareDriver(std::string path);
void ReportAndHandleThreats();
void ScanDirectoryRecursively(std::string root);
int AnalyzeFile(std::string fullPath, std::vector<std::string>& reasons);
bool CheckStartupStatus(std::string path);
bool IsSimilar(std::string s1, std::string s2);
void QuarantineFile(std::string sourcePath);
void RestoreQuarantine();
void ScanNetworkActivity();

std::string GetFileHash(std::string filename) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;

    std::ifstream file(filename, std::ios::binary);
    if (!file) return "error";

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        BCryptHashData(hHash, (PBYTE)buffer, (ULONG)file.gcount(), 0);
    }
    BCryptHashData(hHash, (PBYTE)buffer, (ULONG)file.gcount(), 0);

    BCryptFinishHash(hHash, pbHash, cbHash, 0);

    std::string hashStr = "";
    for (DWORD i = 0; i < cbHash; i++) {
        char hex[3];
        sprintf(hex, "%02x", pbHash[i]);
        hashStr += hex;
    }

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);

    return hashStr;
}

bool IsFileSigned(std::string path) {
    std::wstring wpath(path.begin(), path.end());
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wpath.c_str();

    GUID actionID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtData = { 0 };
    wtData.cbStruct = sizeof(WINTRUST_DATA);
    wtData.dwUIChoice = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice = WTD_CHOICE_FILE;
    wtData.pFile = &fileInfo;
    wtData.dwStateAction = WTD_STATEACTION_IGNORE;
    wtData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    LONG result = WinVerifyTrust(NULL, &actionID, &wtData);
    return result == ERROR_SUCCESS;
}

bool IsHardwareDriver(std::string path) {
    std::string fileName = fs::path(path).filename().string();
    std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);
    std::string pathLower = path;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

    for (const auto& d : driverWhitelist) {
        if (fileName.find(d) != std::string::npos || pathLower.find("\\pusat\\") != std::string::npos || pathLower.find("\\peripheral\\") != std::string::npos)
            return true;
    }
    return false;
}

bool CheckStartupStatus(std::string path) {
    auto checkRegistry = [&](HKEY hRoot, const char* subKey) {
        HKEY hKey;
        if (RegOpenKeyExA(hRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char valueName[1024];
            DWORD valueNameLen = 1024;
            char data[1024];
            DWORD dataLen = 1024;
            DWORD i = 0;
            while (RegEnumValueA(hKey, i++, valueName, &valueNameLen, NULL, NULL, (LPBYTE)data, &dataLen) == ERROR_SUCCESS) {
                std::string sData = data;
                std::transform(sData.begin(), sData.end(), sData.begin(), ::tolower);
                std::string sPath = path;
                std::transform(sPath.begin(), sPath.end(), sPath.begin(), ::tolower);
                if (sData.find(sPath) != std::string::npos) {
                    RegCloseKey(hKey);
                    return true;
                }
                valueNameLen = 1024;
                dataLen = 1024;
            }
            RegCloseKey(hKey);
        }
        return false;
    };
    return checkRegistry(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run") ||
           checkRegistry(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
}

bool IsSimilar(std::string s1, std::string s2) {
    if (s1 == s2 || std::abs((int)s1.length() - (int)s2.length()) > 1) return false;
    int diffs = 0;
    int minLen = std::min((int)s1.length(), (int)s2.length());
    for (int i = 0; i < minLen; i++) if (s1[i] != s2[i]) diffs++;
    return diffs > 0 && diffs <= 2;
}

void QuarantineFile(std::string sourcePath) {
    try {
        std::string fileName = fs::path(sourcePath).filename().string();
        std::string destPath = quarantineDir + "\\" + fileName + ".jny_locked";
        std::string mapPath = quarantineDir + "\\" + fileName + ".map";
        if (fs::exists(sourcePath)) {
            std::ofstream mapFile(mapPath);
            mapFile << sourcePath;
            mapFile.close();
            fs::rename(sourcePath, destPath);
        }
    } catch (...) {}
}

void RestoreQuarantine() {
    for (auto& p : fs::directory_iterator(quarantineDir)) {
        if (p.path().extension() == ".map") {
            try {
                std::ifstream mapFile(p.path());
                std::string originalPath;
                std::getline(mapFile, originalPath);
                mapFile.close();
                std::string lockedFile = p.path().string();
                size_t pos = lockedFile.find(".map");
                lockedFile.replace(pos, 4, ".jny_locked");
                if (fs::exists(lockedFile)) {
                    fs::create_directories(fs::path(originalPath).parent_path());
                    fs::rename(lockedFile, originalPath);
                    fs::remove(p.path());
                }
            } catch (...) {}
        }
    }
}

void ScanNetworkActivity() {
    std::cout << "\n[SENTINEL NETWORK] Analyzing Unsigned & External Connections..." << std::endl;
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD dwSize = 0;
    GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
    GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    char winBuf[MAX_PATH];
    GetWindowsDirectoryA(winBuf, MAX_PATH);
    std::string winPath = winBuf;
    std::transform(winPath.begin(), winPath.end(), winPath.begin(), ::tolower);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                char pathBuf[MAX_PATH];
                DWORD dwPathSize = MAX_PATH;
                if (QueryFullProcessImageNameA(hProc, 0, pathBuf, &dwPathSize)) {
                    std::string path = pathBuf;
                    if (!IsHardwareDriver(path) && GetFileHash(path) != currentSelfHash) {
                        bool isSigned = IsFileSigned(path);
                        std::string pathLower = path;
                        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);
                        bool isTrusted = pathLower.find("windowsapps") != std::string::npos || pathLower.find("winget") != std::string::npos;
                        bool isSys = pathLower.find(winPath) != std::string::npos || pathLower.find("\\windows\\") != std::string::npos;

                        if (!isSigned && !isTrusted && !isSys) {
                            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                                if (pTcpTable->table[i].dwOwningPid == pe.th32ProcessID && pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                                    if (detectedThreats.find(path) == detectedThreats.end()) {
                                        detectedThreats[path] = { 100, {"Unsigned process with active network activity"} };
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    free(pTcpTable);
    ReportAndHandleThreats();
}

int AnalyzeFile(std::string fullPath, std::vector<std::string>& reasons) {
    if (IsHardwareDriver(fullPath)) return 0;
    int threatScore = 0;
    std::string fileName = fs::path(fullPath).stem().string();
    std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);
    std::string pathLower = fullPath;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

    bool isSigned = IsFileSigned(fullPath);
    bool isStartup = CheckStartupStatus(fullPath);
    bool isTrusted = pathLower.find("\\windowsapps\\") != std::string::npos || pathLower.find("\\microsoft\\winget\\") != std::string::npos;

    if (!isSigned) {
        if (!isTrusted) {
            threatScore += 50;
            reasons.push_back("No Valid Digital Signature");
        } else {
            threatScore += 10;
            reasons.push_back("Unsigned but verified Package Origin");
        }
    }

    for (const auto& workspace : developerWorkspaces) {
        std::string wsLower = workspace;
        std::transform(wsLower.begin(), wsLower.end(), wsLower.begin(), ::tolower);
        if (pathLower.find(wsLower) == 0) {
            threatScore -= 30;
            reasons.push_back("Safe Zone: Developer Workspace");
        }
    }

    if (isStartup && !isSigned && !isTrusted) {
        threatScore += 50;
        reasons.push_back("Persistence Alert: Unsigned file in Startup");
    }

    for (const auto& service : criticalServices) {
        if (fileName == service && pathLower.find("c:\\windows\\system32") == std::string::npos) {
            threatScore += 70;
            reasons.push_back("Location Anomaly: " + service + " masquerading");
        }
        if (IsSimilar(fileName, service)) {
            threatScore += 50;
            reasons.push_back("Typosquatting: Mimicking " + service);
        }
    }
    return threatScore;
}

void ScanDirectoryRecursively(std::string root) {
    std::string pathLower = root;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);
    if (pathLower.find("c:\\windows") != std::string::npos || pathLower.find("winsxs") != std::string::npos) return;

    try {
        for (auto& p : fs::directory_iterator(root)) {
            if (p.is_directory()) {
                ScanDirectoryRecursively(p.path().string());
            } else if (p.path().extension() == ".exe") {
                if (GetFileHash(p.path().string()) == currentSelfHash) continue;
                std::vector<std::string> reasons;
                int score = AnalyzeFile(p.path().string(), reasons);
                if (score >= 40) {
                    detectedThreats[p.path().string()] = { std::min(score, 100), reasons };
                }
            }
        }
    } catch (...) {}
}

void ReportAndHandleThreats() {
    std::cout << "\n" << std::string(50, '-') << std::endl;
    std::cout << "[+] Analysis Finished. Total Threats: " << detectedThreats.size() << std::endl;

    if (!detectedThreats.empty()) {
        for (auto const& [path, info] : detectedThreats) {
            std::cout << "\n-> " << fs::path(path).filename().string() << " | TOTAL SCORE: " << info.Score << "/100" << std::endl;
            for (const auto& reason : info.Reasons) std::cout << "   [!] " << reason << std::endl;
            std::cout << "   [#] SHA256: " << GetFileHash(path) << std::endl;
        }
        std::cout << "\n[?] Move detected files to secure quarantine? (-y / -n): ";
        std::string choice;
        std::cin >> choice;
        if (choice == "-y") {
            for (auto const& [path, info] : detectedThreats) QuarantineFile(path);
            std::cout << "\n[+] Isolation complete." << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    currentSelfHash = GetFileHash(selfPath);

    if (!fs::exists(quarantineDir)) fs::create_directories(quarantineDir);

    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--restore") {
            RestoreQuarantine();
            return 0;
        }
        if (arg == "--network-scan") {
            ScanNetworkActivity();
            return 0;
        }
    }

    std::string path = (argc > 1) ? argv[1] : fs::current_path().string();
    std::cout << "\n[SENTINEL CORE v" << version << "] Precision Scan Initiated: " << path << std::endl;

    ScanDirectoryRecursively(path);
    ReportAndHandleThreats();

    std::cout << "\n[PRESS ENTER TO EXIT]" << std::endl;
    std::cin.ignore();
    std::cin.get();
    return 0;
}
