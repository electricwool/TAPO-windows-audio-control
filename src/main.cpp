#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincred.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include <objbase.h>

#include "resource.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#pragma comment(lib, "ole32.lib")

#ifndef __IAudioMeterInformation_INTERFACE_DEFINED__
struct IAudioMeterInformation : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetPeakValue(float* peak) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMeteringChannelCount(UINT* channelCount) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetChannelsPeakValues(UINT channelCount,
                                                            float* peakValues) = 0;
    virtual HRESULT STDMETHODCALLTYPE QueryHardwareSupport(DWORD* hardwareSupport) = 0;
};
#endif

namespace {

constexpr GUID kIidAudioMeterInformation{
    0xc02216f6, 0x8c67, 0x4b5b, {0x9d, 0x00, 0xd0, 0x08, 0xe7, 0x3e, 0x00, 0x64}};
constexpr wchar_t kWindowClass[] = L"TapoAudioWindow";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallback = WM_APP + 1;
constexpr UINT kNotifyMessage = WM_APP + 2;
constexpr UINT kMenuForceOff = 1001;
constexpr UINT kMenuForceOn = 1002;
constexpr UINT kMenuOn = 1003;
constexpr UINT kMenuOff = 1004;
constexpr UINT kMenuExit = 1005;
constexpr auto kRetryDelay = std::chrono::seconds(30);
constexpr auto kAudioPollInterval = std::chrono::milliseconds(100);

struct Config {
    std::wstring model;
    std::wstring ip;
    std::wstring username;
    unsigned idleTimeoutSeconds = 600;
};

struct Credential {
    std::wstring username;
    std::wstring password;
};

enum class OverrideMode {
    Automatic,
    HoldOff,
    HoldOn
};

class CredentialVariantMismatch : public std::runtime_error {
public:
    CredentialVariantMismatch()
        : std::runtime_error("The Tapo switch uses another KLAP credential variant.") {}
};

struct TapoCredentialUiInfo {
    DWORD cbSize;
    HWND hwndParent;
    PCWSTR pszMessageText;
    PCWSTR pszCaptionText;
    HBITMAP hbmBanner;
};

HWND g_window = nullptr;
NOTIFYICONDATAW g_icon{};
Config g_config;
Credential g_credential;
std::atomic<OverrideMode> g_mode{OverrideMode::Automatic};
std::atomic<bool> g_exit{false};
std::mutex g_workMutex;
std::condition_variable g_workChanged;
std::optional<bool> g_manualRequest;
std::mutex g_notifyMutex;
std::wstring g_lastError;

std::wstring ExeDirectory() {
    std::wstring path(32768, L'\0');
    const DWORD size = GetModuleFileNameW(nullptr, path.data(),
                                          static_cast<DWORD>(path.size()));
    if (size == 0 || size >= path.size()) {
        throw std::runtime_error("Could not locate the application executable.");
    }
    path.resize(size);
    const auto slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        throw std::runtime_error("Could not determine the application directory.");
    }
    return path.substr(0, slash + 1);
}

std::string ReadFileUtf8(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Could not open config.json beside the application.");
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0 ||
        fileSize.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        throw std::runtime_error("config.json is too large or could not be read.");
    }

    std::string contents(static_cast<size_t>(fileSize.QuadPart), '\0');
    size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD bytesToRead = static_cast<DWORD>(
            std::min(contents.size() - offset,
                     static_cast<size_t>(std::numeric_limits<DWORD>::max())));
        DWORD bytesRead = 0;
        if (!ReadFile(file, contents.data() + offset, bytesToRead, &bytesRead, nullptr) ||
            bytesRead == 0) {
            CloseHandle(file);
            throw std::runtime_error("Could not read config.json beside the application.");
        }
        offset += bytesRead;
    }
    CloseHandle(file);
    return contents;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                          value.data(),
                                          static_cast<int>(value.size()),
                                          nullptr, 0);
    if (count <= 0) {
        throw std::runtime_error("config.json is not valid UTF-8.");
    }
    std::wstring result(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), count);
    return result;
}

std::string FindJsonString(const std::string& json, const std::string& key,
                           const std::string& fallback = {}) {
    const std::string quotedKey = "\"" + key + "\"";
    size_t pos = json.find(quotedKey);
    if (pos == std::string::npos) return fallback;
    pos = json.find(':', pos + quotedKey.size());
    if (pos == std::string::npos) return fallback;
    pos = json.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos || json[pos] != '"') return fallback;
    ++pos;
    std::string value;
    while (pos < json.size()) {
        const char ch = json[pos++];
        if (ch == '"') return value;
        if (ch == '\\') {
            if (pos >= json.size()) break;
            const char escaped = json[pos++];
            if (escaped == '"' || escaped == '\\' || escaped == '/') {
                value.push_back(escaped);
            } else if (escaped == 'n') {
                value.push_back('\n');
            } else if (escaped == 'r') {
                value.push_back('\r');
            } else if (escaped == 't') {
                value.push_back('\t');
            } else {
                throw std::runtime_error("Unsupported escape in config.json.");
            }
        } else {
            value.push_back(ch);
        }
    }
    throw std::runtime_error("Unterminated string in config.json.");
}

unsigned FindJsonUnsigned(const std::string& json, const std::string& key,
                          unsigned fallback) {
    const std::string quotedKey = "\"" + key + "\"";
    size_t pos = json.find(quotedKey);
    if (pos == std::string::npos) return fallback;
    pos = json.find(':', pos + quotedKey.size());
    if (pos == std::string::npos) return fallback;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                 json[pos] == '\r' || json[pos] == '\n')) {
        ++pos;
    }
    unsigned result = 0;
    const char* begin = json.data() + pos;
    const char* end = json.data() + json.size();
    const auto parsed = std::from_chars(begin, end, result);
    if (parsed.ec != std::errc{} || result == 0 || result > 86400) {
        throw std::runtime_error("idle_timeout_seconds must be between 1 and 86400.");
    }
    return result;
}

Config LoadConfig() {
    const std::string json = ReadFileUtf8(ExeDirectory() + L"config.json");
    Config config;
    config.model = Utf8ToWide(FindJsonString(json, "model"));
    config.ip = Utf8ToWide(FindJsonString(json, "ip_address"));
    config.username = Utf8ToWide(FindJsonString(json, "tapo_username"));
    config.idleTimeoutSeconds =
        FindJsonUnsigned(json, "idle_timeout_seconds", 600);

    if (config.model.empty()) {
        throw std::runtime_error("Set the target switch model in config.json.");
    }
    if (config.ip.empty()) {
        throw std::runtime_error("Set the target switch IP address in config.json.");
    }
    if (config.username.empty() || config.username == L"your-tapo-account-email") {
        throw std::runtime_error("Set tapo_username to the Tapo account email in config.json.");
    }
    return config;
}

std::wstring CredentialTarget(const Config& config) {
    std::wstring target = L"TapoAudio:";
    for (const wchar_t ch : config.ip) {
        target.push_back(ch == L':' ? L'-' : ch);
    }
    return target;
}

Credential LoadOrPromptCredential(HWND owner, const Config& config) {
    const std::wstring target = CredentialTarget(config);
    PCREDENTIALW stored = nullptr;
    if (CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &stored)) {
        Credential result;
        result.username = stored->UserName ? stored->UserName : L"";
        if (stored->CredentialBlobSize % sizeof(wchar_t) != 0) {
            CredFree(stored);
            throw std::runtime_error("Stored Tapo credentials have an invalid format.");
        }
        const auto* password = reinterpret_cast<const wchar_t*>(stored->CredentialBlob);
        result.password.assign(password,
                                stored->CredentialBlobSize / sizeof(wchar_t));
        CredFree(stored);
        if (result.username == config.username && !result.password.empty()) {
            return result;
        }
    }

    std::vector<wchar_t> user(512, L'\0');
    std::vector<wchar_t> password(512, L'\0');
    wcsncpy_s(user.data(), user.size(), config.username.c_str(), _TRUNCATE);
    TapoCredentialUiInfo ui{};
    ui.cbSize = sizeof(ui);
    ui.hwndParent = owner;
    ui.pszCaptionText = L"TapoAudio account setup";
    ui.pszMessageText =
        L"Enter the TP-Link/Tapo account password for this local smart switch.";
    BOOL save = FALSE;
    using CredentialPrompt = DWORD(WINAPI*)(
        const TapoCredentialUiInfo*, PCWSTR, PVOID, DWORD, PWSTR, ULONG, PWSTR,
        ULONG, BOOL*, DWORD);
    HMODULE credentialUi = LoadLibraryW(L"credui.dll");
    if (!credentialUi) {
        throw std::runtime_error("Windows Credential UI is unavailable.");
    }
    const auto prompt = reinterpret_cast<CredentialPrompt>(
        GetProcAddress(credentialUi, "CredUIPromptForCredentialsW"));
    const DWORD status =
        prompt ? prompt(&ui, target.c_str(), nullptr, 0, user.data(),
                        static_cast<ULONG>(user.size()), password.data(),
                        static_cast<ULONG>(password.size()), &save,
                        0x00040000 | 0x00000080 | 0x00000002)
               : ERROR_PROC_NOT_FOUND;
    FreeLibrary(credentialUi);
    if (status != ERROR_SUCCESS) {
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        throw std::runtime_error("Tapo account setup was cancelled.");
    }
    if (config.username != user.data()) {
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        throw std::runtime_error("The entered username must match tapo_username in config.json.");
    }
    const size_t passwordLength = wcslen(password.data());
    if (passwordLength == 0) {
        throw std::runtime_error("The Tapo account password cannot be empty.");
    }

    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(target.c_str());
    credential.UserName = const_cast<LPWSTR>(config.username.c_str());
    credential.CredentialBlobSize =
        static_cast<DWORD>(passwordLength * sizeof(wchar_t));
    credential.CredentialBlob =
        reinterpret_cast<LPBYTE>(password.data());
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    if (!CredWriteW(&credential, 0)) {
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        throw std::runtime_error("Windows Credential Manager could not store the Tapo password.");
    }
    Credential result{config.username, std::wstring(password.data(), passwordLength)};
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    return result;
}

std::vector<unsigned char> CryptoHash(LPCWSTR algorithm,
                                      const std::vector<unsigned char>& input) {
    BCRYPT_ALG_HANDLE provider = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    DWORD hashSize = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&provider, algorithm, nullptr, 0);
    if (status < 0) throw std::runtime_error("Windows cryptography provider is unavailable.");
    status = BCryptGetProperty(provider, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&objectSize),
                               sizeof(objectSize), &resultSize, 0);
    if (status >= 0) {
        status = BCryptGetProperty(provider, BCRYPT_HASH_LENGTH,
                                   reinterpret_cast<PUCHAR>(&hashSize),
                                   sizeof(hashSize), &resultSize, 0);
    }
    if (status >= 0) {
        object.resize(objectSize);
        digest.resize(hashSize);
        status = BCryptCreateHash(provider, &hash, object.data(), objectSize,
                                  nullptr, 0, 0);
    }
    if (status >= 0 && !input.empty()) {
        status = BCryptHashData(hash, const_cast<PUCHAR>(input.data()),
                                static_cast<ULONG>(input.size()), 0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(hash, digest.data(), hashSize, 0);
    }
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(provider, 0);
    if (status < 0) throw std::runtime_error("Windows cryptographic operation failed.");
    return digest;
}

std::vector<unsigned char> Join(
    std::initializer_list<std::vector<unsigned char>> parts) {
    std::vector<unsigned char> result;
    size_t total = 0;
    for (const auto& part : parts) total += part.size();
    result.reserve(total);
    for (const auto& part : parts) {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

std::vector<unsigned char> ToBytes(const std::string& value) {
    return {value.begin(), value.end()};
}

std::vector<unsigned char> AesCbc(bool encrypt,
                                  const std::vector<unsigned char>& key,
                                  const std::vector<unsigned char>& iv,
                                  const std::vector<unsigned char>& input) {
    BCRYPT_ALG_HANDLE provider = nullptr;
    BCRYPT_KEY_HANDLE cryptoKey = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    std::vector<unsigned char> keyObject;
    std::vector<unsigned char> data = input;
    if (encrypt) {
        const unsigned char pad =
            static_cast<unsigned char>(16 - (data.size() % 16));
        data.insert(data.end(), pad, pad);
    } else if (data.empty() || data.size() % 16 != 0) {
        throw std::runtime_error("Tapo device returned malformed encrypted data.");
    }
    std::vector<unsigned char> output(data.size() + 16);

    NTSTATUS status =
        BCryptOpenAlgorithmProvider(&provider, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status >= 0) {
        status = BCryptSetProperty(
            provider, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    }
    if (status >= 0) {
        status = BCryptGetProperty(provider, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&objectSize),
                                   sizeof(objectSize), &resultSize, 0);
    }
    if (status >= 0) {
        keyObject.resize(objectSize);
        status = BCryptGenerateSymmetricKey(
            provider, &cryptoKey, keyObject.data(), objectSize,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    }
    ULONG outputSize = 0;
    std::vector<unsigned char> mutableIv = iv;
    if (status >= 0) {
        status = encrypt
                     ? BCryptEncrypt(cryptoKey, data.data(),
                                     static_cast<ULONG>(data.size()), nullptr,
                                     mutableIv.data(),
                                     static_cast<ULONG>(mutableIv.size()),
                                     output.data(),
                                     static_cast<ULONG>(output.size()),
                                     &outputSize, 0)
                     : BCryptDecrypt(cryptoKey, data.data(),
                                     static_cast<ULONG>(data.size()), nullptr,
                                     mutableIv.data(),
                                     static_cast<ULONG>(mutableIv.size()),
                                     output.data(),
                                     static_cast<ULONG>(output.size()),
                                     &outputSize, 0);
    }
    if (cryptoKey) BCryptDestroyKey(cryptoKey);
    if (provider) BCryptCloseAlgorithmProvider(provider, 0);
    if (status < 0) throw std::runtime_error("Tapo AES encryption/decryption failed.");
    output.resize(outputSize);

    if (!encrypt) {
        if (output.empty()) throw std::runtime_error("Tapo reply had invalid padding.");
        const unsigned char pad = output.back();
        if (pad == 0 || pad > 16 || pad > output.size()) {
            throw std::runtime_error("Tapo reply had invalid padding.");
        }
        for (size_t i = output.size() - pad; i < output.size(); ++i) {
            if (output[i] != pad) throw std::runtime_error("Tapo reply had invalid padding.");
        }
        output.resize(output.size() - pad);
    }
    return output;
}

struct HttpReply {
    DWORD status = 0;
    std::vector<unsigned char> body;
    std::wstring setCookie;
};

HttpReply HttpPost(const std::wstring& host, const std::wstring& path,
                   const std::vector<unsigned char>& body,
                   const std::wstring& cookie = L"") {
    HINTERNET session = WinHttpOpen(L"TapoAudio/1.0",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) throw std::runtime_error("Could not create a local HTTP session.");
    WinHttpSetTimeouts(session, 2500, 2500, 2500, 2500);
    HINTERNET connection = WinHttpConnect(session, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!connection) {
        WinHttpCloseHandle(session);
        throw std::runtime_error("Could not connect to the Tapo switch.");
    }
    HINTERNET request = WinHttpOpenRequest(
        connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        throw std::runtime_error("Could not open a Tapo local-control request.");
    }
    if (!cookie.empty()) {
        const std::wstring header = L"Cookie: " + cookie + L"\r\n";
        WinHttpAddRequestHeaders(request, header.c_str(),
                                 static_cast<DWORD>(header.size()),
                                 WINHTTP_ADDREQ_FLAG_ADD);
    }
    const BOOL sent = WinHttpSendRequest(
        request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.empty() ? WINHTTP_NO_REQUEST_DATA
                     : const_cast<unsigned char*>(body.data()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        throw std::runtime_error("No response from the Tapo switch.");
    }
    HttpReply reply;
    DWORD statusSize = sizeof(reply.status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &reply.status, &statusSize,
                             WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        throw std::runtime_error("Could not read the Tapo response status.");
    }
    DWORD cookieSize = 0;
    WinHttpQueryHeaders(request, WINHTTP_QUERY_SET_COOKIE,
                        WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &cookieSize,
                        WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cookieSize > sizeof(wchar_t)) {
        reply.setCookie.resize(cookieSize / sizeof(wchar_t));
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_SET_COOKIE,
                                WINHTTP_HEADER_NAME_BY_INDEX,
                                reply.setCookie.data(), &cookieSize,
                                WINHTTP_NO_HEADER_INDEX)) {
            while (!reply.setCookie.empty() && reply.setCookie.back() == L'\0') {
                reply.setCookie.pop_back();
            }
        } else {
            reply.setCookie.clear();
        }
    }
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        const size_t offset = reply.body.size();
        reply.body.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(request, reply.body.data() + offset, available, &read)) {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            throw std::runtime_error("Could not read the Tapo response body.");
        }
        reply.body.resize(offset + read);
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return reply;
}

std::wstring ExtractSessionCookie(const std::wstring& setCookie) {
    constexpr wchar_t prefix[] = L"TP_SESSIONID=";
    const size_t start = setCookie.find(prefix);
    if (start == std::wstring::npos) return {};
    const size_t valueStart = start + (sizeof(prefix) / sizeof(wchar_t)) - 1;
    const size_t end = setCookie.find(L';', valueStart);
    return setCookie.substr(valueStart,
                            end == std::wstring::npos ? end : end - valueStart);
}

std::vector<unsigned char> BigEndianInt32(uint32_t value) {
    return {static_cast<unsigned char>((value >> 24) & 0xff),
            static_cast<unsigned char>((value >> 16) & 0xff),
            static_cast<unsigned char>((value >> 8) & 0xff),
            static_cast<unsigned char>(value & 0xff)};
}

class TapoClient {
public:
    TapoClient(const Config& config, const Credential& credential)
        : config_(config), credential_(credential) {}

    void SetPower(bool on) {
        const std::wstring& ip = config_.ip;
        Session session;
        try {
            session = EstablishSession(ip, MakeAuthHashV1(), false);
        } catch (const CredentialVariantMismatch&) {
            session = EstablishSession(ip, MakeAuthHashV2(), true);
        }

        const std::string request =
            std::string("{\"method\":\"set_device_info\",\"params\":{\"device_on\":") +
            (on ? "true" : "false") + "}}";
        const auto encrypted = AesCbc(true, session.key, session.iv,
                                      ToBytes(request));
        const auto signature = CryptoHash(
            BCRYPT_SHA256_ALGORITHM,
            Join({session.signatureBase, session.sequenceBytes, encrypted}));
        std::vector<unsigned char> payload = signature;
        payload.insert(payload.end(), encrypted.begin(), encrypted.end());
        const std::wstring requestPath =
            L"/app/request?seq=" +
            std::to_wstring(static_cast<int32_t>(session.sequence));
        HttpReply response =
            HttpPost(ip, requestPath, payload, L"TP_SESSIONID=" + session.cookie);
        if (response.status != 200 || response.body.size() < 48) {
            throw std::runtime_error("Tapo rejected the switch power command.");
        }
        const std::vector<unsigned char> responseCipher(response.body.begin() + 32,
                                                        response.body.end());
        const auto decrypted =
            AesCbc(false, session.key, session.iv, responseCipher);
        const std::string responseText(decrypted.begin(), decrypted.end());
        if (responseText.find("\"error_code\":0") == std::string::npos &&
            responseText.find("\"err_code\":0") == std::string::npos) {
            throw std::runtime_error("Tapo returned an unsuccessful switch command.");
        }
    }

private:
    struct Session {
        std::wstring cookie;
        std::vector<unsigned char> key;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> sequenceBytes;
        std::vector<unsigned char> signatureBase;
        uint32_t sequence = 0;
    };

    std::vector<unsigned char> MakeAuthHashV1() const {
        const auto user = ToBytes(WideToUtf8(credential_.username));
        const auto password = ToBytes(WideToUtf8(credential_.password));
        const auto userHash = CryptoHash(BCRYPT_MD5_ALGORITHM, user);
        const auto passwordHash = CryptoHash(BCRYPT_MD5_ALGORITHM, password);
        return CryptoHash(BCRYPT_MD5_ALGORITHM, Join({userHash, passwordHash}));
    }

    std::vector<unsigned char> MakeAuthHashV2() const {
        const auto user = ToBytes(WideToUtf8(credential_.username));
        const auto password = ToBytes(WideToUtf8(credential_.password));
        const auto userHash = CryptoHash(BCRYPT_SHA1_ALGORITHM, user);
        const auto passwordHash = CryptoHash(BCRYPT_SHA1_ALGORITHM, password);
        return CryptoHash(BCRYPT_SHA256_ALGORITHM, Join({userHash, passwordHash}));
    }

    Session EstablishSession(const std::wstring& ip,
                             const std::vector<unsigned char>& authHash,
                             bool version2) const {
        const auto localSeed = RandomBytes(16);
        HttpReply first = HttpPost(ip, L"/app/handshake1", localSeed);
        if (first.status != 200 || first.body.size() != 48) {
            throw std::runtime_error("Tapo KLAP handshake failed; check local-control compatibility and firmware.");
        }
        std::vector<unsigned char> remoteSeed(first.body.begin(),
                                              first.body.begin() + 16);
        std::vector<unsigned char> serverHash(first.body.begin() + 16,
                                              first.body.end());
        const auto expectedHash =
            version2
                ? CryptoHash(BCRYPT_SHA256_ALGORITHM,
                             Join({localSeed, remoteSeed, authHash}))
                : CryptoHash(BCRYPT_SHA256_ALGORITHM, Join({localSeed, authHash}));
        if (expectedHash != serverHash) {
            throw CredentialVariantMismatch();
        }
        const std::wstring cookie = ExtractSessionCookie(first.setCookie);
        if (cookie.empty()) {
            throw std::runtime_error("Tapo did not return a local session cookie.");
        }
        const auto secondHash =
            version2
                ? CryptoHash(BCRYPT_SHA256_ALGORITHM,
                             Join({remoteSeed, localSeed, authHash}))
                : CryptoHash(BCRYPT_SHA256_ALGORITHM, Join({remoteSeed, authHash}));
        HttpReply second = HttpPost(ip, L"/app/handshake2", secondHash,
                                    L"TP_SESSIONID=" + cookie);
        if (second.status != 200) {
            throw std::runtime_error("Tapo rejected the KLAP session handshake.");
        }

        const auto keyDigest = CryptoHash(
            BCRYPT_SHA256_ALGORITHM,
            Join({ToBytes("lsk"), localSeed, remoteSeed, authHash}));
        const auto fullIv = CryptoHash(
            BCRYPT_SHA256_ALGORITHM,
            Join({ToBytes("iv"), localSeed, remoteSeed, authHash}));
        const auto signatureDigest = CryptoHash(
            BCRYPT_SHA256_ALGORITHM,
            Join({ToBytes("ldk"), localSeed, remoteSeed, authHash}));
        Session session;
        session.cookie = cookie;
        session.key.assign(keyDigest.begin(), keyDigest.begin() + 16);
        session.iv.assign(fullIv.begin(), fullIv.begin() + 12);
        session.signatureBase.assign(signatureDigest.begin(),
                                     signatureDigest.begin() + 28);
        session.sequence =
            (static_cast<uint32_t>(fullIv[28]) << 24) |
            (static_cast<uint32_t>(fullIv[29]) << 16) |
            (static_cast<uint32_t>(fullIv[30]) << 8) |
            static_cast<uint32_t>(fullIv[31]);
        ++session.sequence;
        session.sequenceBytes = BigEndianInt32(session.sequence);
        session.iv.insert(session.iv.end(), session.sequenceBytes.begin(),
                          session.sequenceBytes.end());
        return session;
    }

    static std::vector<unsigned char> RandomBytes(size_t count) {
        std::vector<unsigned char> bytes(count);
        if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            throw std::runtime_error("Could not create Tapo handshake randomness.");
        }
        return bytes;
    }

    static std::string WideToUtf8(const std::wstring& value) {
        if (value.empty()) return {};
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                              value.data(),
                                              static_cast<int>(value.size()),
                                              nullptr, 0, nullptr, nullptr);
        if (size <= 0) throw std::runtime_error("Tapo account contains invalid characters.");
        std::string result(static_cast<size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), result.data(), size,
                            nullptr, nullptr);
        return result;
    }

    const Config& config_;
    const Credential& credential_;
};

class AudioMonitor {
public:
    AudioMonitor() {
        const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(initialized)) {
            throw std::runtime_error("Windows could not initialize audio monitoring.");
        }
        comInitialized_ = true;

        HRESULT result = CoCreateInstance(
            __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
            __uuidof(IMMDeviceEnumerator),
            reinterpret_cast<void**>(&enumerator_));
        if (FAILED(result)) {
            Release();
            throw std::runtime_error("Windows could not access playback audio devices.");
        }
        try {
            RefreshEndpoint();
        } catch (const std::exception&) {
            Release();
            throw;
        }
    }

    ~AudioMonitor() {
        Release();
    }

    AudioMonitor(const AudioMonitor&) = delete;
    AudioMonitor& operator=(const AudioMonitor&) = delete;

    bool IsActive() {
        if (std::chrono::steady_clock::now() >= nextRefresh_) {
            RefreshEndpoint();
        }
        float peak = 0.0f;
        if (FAILED(meter_->GetPeakValue(&peak))) {
            throw std::runtime_error("Windows could not read the playback audio level.");
        }
        return peak > 0.0f;
    }

private:
    void RefreshEndpoint() {
        IMMDevice* endpoint = nullptr;
        IAudioMeterInformation* meter = nullptr;
        HRESULT result = enumerator_->GetDefaultAudioEndpoint(
            eRender, eConsole, &endpoint);
        if (SUCCEEDED(result)) {
            result = endpoint->Activate(
                kIidAudioMeterInformation, CLSCTX_ALL, nullptr,
                reinterpret_cast<void**>(&meter));
        }
        if (FAILED(result)) {
            if (meter) meter->Release();
            if (endpoint) endpoint->Release();
            throw std::runtime_error("Windows could not access the default playback audio meter.");
        }
        if (meter_) meter_->Release();
        if (endpoint_) endpoint_->Release();
        endpoint_ = endpoint;
        meter_ = meter;
        nextRefresh_ = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    }

    void Release() {
        if (meter_) {
            meter_->Release();
            meter_ = nullptr;
        }
        if (endpoint_) {
            endpoint_->Release();
            endpoint_ = nullptr;
        }
        if (enumerator_) {
            enumerator_->Release();
            enumerator_ = nullptr;
        }
        if (comInitialized_) {
            CoUninitialize();
            comInitialized_ = false;
        }
    }

    IMMDeviceEnumerator* enumerator_ = nullptr;
    IMMDevice* endpoint_ = nullptr;
    IAudioMeterInformation* meter_ = nullptr;
    bool comInitialized_ = false;
    std::chrono::steady_clock::time_point nextRefresh_{};
};

void NotifyError(const std::string& message) {
    try {
        std::wstring text = Utf8ToWide(message);
        {
            std::lock_guard<std::mutex> lock(g_notifyMutex);
            g_lastError = std::move(text);
        }
        if (g_window) PostMessageW(g_window, kNotifyMessage, 0, 0);
    } catch (...) {
        OutputDebugStringW(L"TapoAudio: operation failed and its error could not be decoded.\n");
    }
}

bool PerformPowerRequest(bool on) {
    try {
        TapoClient client(g_config, g_credential);
        client.SetPower(on);
        return true;
    } catch (const std::exception& error) {
        NotifyError(error.what());
        return false;
    }
}

void AutomationWorker() {
    using Clock = std::chrono::steady_clock;
    try {
        AudioMonitor audioMonitor;
        std::optional<Clock::time_point> lastAudio;
        std::optional<Clock::time_point> lastAttempt;
        std::optional<bool> appliedState;
        std::optional<bool> desiredState;
        while (!g_exit.load()) {
            std::optional<bool> manual;
            {
                std::unique_lock<std::mutex> lock(g_workMutex);
                g_workChanged.wait_for(lock, kAudioPollInterval, [] {
                    return g_exit.load() || g_manualRequest.has_value();
                });
                if (g_exit.load()) break;
                manual.swap(g_manualRequest);
            }

            if (manual) {
                desiredState = manual;
                if (*manual) lastAudio = Clock::now();
                lastAttempt = Clock::now();
                if (PerformPowerRequest(*manual)) {
                    appliedState = manual;
                }
            }

            if (audioMonitor.IsActive()) {
                lastAudio = Clock::now();
                desiredState = true;
            } else if (lastAudio &&
                       Clock::now() - *lastAudio >=
                           std::chrono::seconds(g_config.idleTimeoutSeconds)) {
                desiredState = false;
            }
            const OverrideMode mode = g_mode.load();
            if (mode == OverrideMode::HoldOn) {
                desiredState = true;
            } else if (mode == OverrideMode::HoldOff) {
                desiredState = false;
            }
            const auto now = Clock::now();
            if (desiredState && appliedState != desiredState &&
                (!lastAttempt || now - *lastAttempt >= kRetryDelay)) {
                lastAttempt = Clock::now();
                if (PerformPowerRequest(*desiredState)) {
                    appliedState = desiredState;
                }
            }
        }
    } catch (const std::exception& error) {
        NotifyError(error.what());
    }
}

void QueuePowerRequest(bool on) {
    {
        std::lock_guard<std::mutex> lock(g_workMutex);
        g_manualRequest = on;
    }
    g_workChanged.notify_one();
}

void UpdateTrayTooltip() {
    if (g_mode == OverrideMode::HoldOff) {
        wcscpy_s(g_icon.szTip, L"TapoAudio - held off until restart");
    } else if (g_mode == OverrideMode::HoldOn) {
        wcscpy_s(g_icon.szTip, L"TapoAudio - held on until restart");
    } else {
        wcscpy_s(g_icon.szTip, L"TapoAudio - automatic");
    }
    Shell_NotifyIconW(NIM_MODIFY, &g_icon);
}

void ShowTrayMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    AppendMenuW(menu, MF_STRING, kMenuForceOff,
                L"Turn off; disable auto-on until restart");
    AppendMenuW(menu, MF_STRING, kMenuForceOn,
                L"Turn on; disable auto-off until restart");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kMenuOn, L"Turn on");
    AppendMenuW(menu, MF_STRING, kMenuOff, L"Turn off");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kMenuExit, L"Exit");

    POINT point{};
    GetCursorPos(&point);
    SetForegroundWindow(hwnd);
    const UINT command =
        TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                       point.x, point.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
    switch (command) {
        case kMenuForceOff:
            g_mode = OverrideMode::HoldOff;
            QueuePowerRequest(false);
            UpdateTrayTooltip();
            break;
        case kMenuForceOn:
            g_mode = OverrideMode::HoldOn;
            QueuePowerRequest(true);
            UpdateTrayTooltip();
            break;
        case kMenuOn:
            QueuePowerRequest(true);
            break;
        case kMenuOff:
            QueuePowerRequest(false);
            break;
        case kMenuExit:
            DestroyWindow(hwnd);
            break;
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case kTrayCallback:
            if (LOWORD(lParam) == WM_RBUTTONUP ||
                LOWORD(lParam) == WM_CONTEXTMENU ||
                LOWORD(lParam) == NIN_SELECT) {
                ShowTrayMenu(hwnd);
            }
            return 0;
        case kNotifyMessage: {
            std::wstring error;
            {
                std::lock_guard<std::mutex> lock(g_notifyMutex);
                error.swap(g_lastError);
            }
            g_icon.dwInfoFlags = NIIF_ERROR;
            g_icon.uFlags |= NIF_INFO;
            wcscpy_s(g_icon.szInfoTitle, L"TapoAudio could not control the switch");
            wcsncpy_s(g_icon.szInfo, error.c_str(), _TRUNCATE);
            Shell_NotifyIconW(NIM_MODIFY, &g_icon);
            g_icon.uFlags &= ~NIF_INFO;
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == kMenuExit) DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_icon);
            g_exit = true;
            g_workChanged.notify_all();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    try {
        g_config = LoadConfig();
        const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE) {
            throw std::runtime_error("Windows COM initialization failed.");
        }

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = WindowProc;
        windowClass.hInstance = instance;
        windowClass.lpszClassName = kWindowClass;
        HICON appIcon = static_cast<HICON>(LoadImageW(
            instance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
            LR_DEFAULTCOLOR | LR_SHARED));
        if (!appIcon) {
            throw std::runtime_error("Could not load the application icon.");
        }
        windowClass.hIcon = appIcon;
        windowClass.hIconSm = appIcon;
        if (!RegisterClassExW(&windowClass)) {
            throw std::runtime_error("Could not register the tray application window.");
        }
        g_window = CreateWindowExW(0, kWindowClass, L"TapoAudio", WS_OVERLAPPED,
                                   0, 0, 0, 0, nullptr, nullptr, instance, nullptr);
        if (!g_window) {
            throw std::runtime_error("Could not create the tray application window.");
        }
        g_credential = LoadOrPromptCredential(g_window, g_config);

        g_icon.cbSize = sizeof(g_icon);
        g_icon.hWnd = g_window;
        g_icon.uID = kTrayIconId;
        g_icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_icon.uCallbackMessage = kTrayCallback;
        g_icon.hIcon = appIcon;
        wcscpy_s(g_icon.szTip, L"TapoAudio - automatic");
        if (!Shell_NotifyIconW(NIM_ADD, &g_icon)) {
            throw std::runtime_error("Windows could not add the system tray icon.");
        }
        g_icon.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &g_icon);

        std::thread worker(AutomationWorker);
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (worker.joinable()) worker.join();
        CoUninitialize();
        return static_cast<int>(message.wParam);
    } catch (const std::exception& error) {
        const std::string message = error.what();
        const int length = MultiByteToWideChar(CP_UTF8, 0, message.c_str(), -1,
                                               nullptr, 0);
        std::wstring wide(static_cast<size_t>(std::max(length, 1)), L'\0');
        if (length > 0) {
            MultiByteToWideChar(CP_UTF8, 0, message.c_str(), -1, wide.data(), length);
        }
        MessageBoxW(nullptr, wide.c_str(), L"TapoAudio setup error",
                    MB_OK | MB_ICONERROR);
        return 1;
    }
}
