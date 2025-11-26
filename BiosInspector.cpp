#include "BiosInspector.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <array>
#include <algorithm>
#include <unordered_map>
#include <cmath>
#include <stdexcept>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

namespace biosinspector {

    // Pequeno helper para rodar comandos e capturar código de saída
    static int runCommand(const std::string& cmd) {
        std::cout << "[CMD] " << cmd << "\n";

    #ifdef _WIN32
        std::array<char, 4096> buffer{};
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) {
            std::cerr << "[!] Falha ao executar comando via _popen.\n";
            return -1;
        }
        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
            std::cout << buffer.data();
        }
        int rc = _pclose(pipe);
        return rc;
    #else
        // em Linux pode usar system mesmo, ou adaptar para popen
        return std::system(cmd.c_str());
    #endif
    }

    // Helpers para hashing SHA 256 você pode colar aqui o código já pronto
    // que você usa no PeCoffAnalyzer.cpp
    // Para este esqueleto, deixo um stub simples
    static std::string sha256Stub(const std::vector<uint8_t>& data) {
        // TODO: substituir pela sua função real de SHA 256
        std::ostringstream oss;
        oss << "sha256_stub_" << std::hex << data.size();
        return oss.str();
    }

    
    // ##################################################
    // ##### metodos do ChipsecExtractor standalone #####
    #ifdef _WIN32
    static fs::path to_extended_path(const fs::path& p) {
        std::wstring ws = p.wstring();
        if (ws.rfind(L"\\\\?\\", 0) == 0 || ws.rfind(L"\\\\.\\", 0) == 0)
            return p;
        if (ws.size() >= 2 && ws[1] == L':') {
            return fs::path(L"\\\\?\\" + ws);
        }
        return p;
    }
    #else
        static fs::path to_extended_path(const fs::path& p) { return p; }
    #endif

    static std::string trim_eol(std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
            s.pop_back();
        }
        return s;
    }

    static std::string escape_ps_single_quotes(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            if (c == '\'') out += "''";
            else out += c;
        }
        return out;
    }

    // lista todos .efi via PowerShell, exatamente como no standalone
    std::vector<fs::path> list_efi_strict_via_powershell(const fs::path& sourceDir) {
        std::vector<fs::path> result;

        std::string dirStr = sourceDir.string();
        std::string dirEsc = escape_ps_single_quotes(dirStr);

        std::string psScript =
            "powershell -NoProfile -Command "
            "\"Get-ChildItem -Recurse -File -LiteralPath '" + dirEsc +
            "' | Where-Object { $_.Extension -eq '.efi' } | ForEach-Object { $_.FullName }\"";

        std::array<char, 4096> buffer{};
        FILE* pipe = _popen(psScript.c_str(), "r");
        if (!pipe) {
            std::cerr << "[!] Falha ao executar PowerShell para listar .efi.\n";
            return result;
        }

        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
            std::string line = trim_eol(buffer.data());
            if (!line.empty()) {
                fs::path p = line;
                result.push_back(p);
            }
        }
        _pclose(pipe);

        return result;
    }

    static fs::path make_unique_dest(const fs::path& destRoot,
                                     const fs::path& fileName) {
        fs::path dest = destRoot / fileName;
        if (!fs::exists(dest)) {
            return dest;
        }

        std::string stem  = dest.stem().string();
        std::string ext   = dest.extension().string();
        int counter       = 1;
        while (true) {
            std::ostringstream oss;
            oss << stem << "_" << counter << ext;
            fs::path candidate = destRoot / oss.str();
            if (!fs::exists(candidate)) {
                return candidate;
            }
            counter++;
        }
    }

    size_t copy_efi_flat_from_list(const std::vector<fs::path>& efiFiles,
                                const fs::path& destRoot) {
        if (!fs::exists(destRoot))
            fs::create_directories(destRoot);

        size_t copied = 0;
        for (const auto& p : efiFiles) {
            fs::path dest = make_unique_dest(destRoot, p.filename());
            std::error_code ec;

            fs::copy_file(
                to_extended_path(p),
                to_extended_path(dest),
                fs::copy_options::overwrite_existing,
                ec
            );

            if (ec) {
                std::cerr << "[!] Falha copiando " << p
                        << " : " << ec.message() << "\n";
                continue;
            }
            std::cout << "[+] Copiado: " << p.string()
                    << " -> " << dest.string() << "\n";
            copied++;
        }
        return copied;
    }

    void move_path_best_effort(const fs::path& src, const fs::path& dst) {
        std::error_code ec;

        fs::create_directories(dst.parent_path());

        fs::rename(to_extended_path(src), to_extended_path(dst), ec);
        if (!ec) {
            std::cout << "[>] Movido: " << src << " -> " << dst << "\n";
            return;
        }

        ec.clear();
        if (fs::is_directory(src)) {
            fs::copy(
                to_extended_path(src),
                to_extended_path(dst),
                fs::copy_options::recursive | fs::copy_options::overwrite_existing,
                ec
            );
            if (ec) {
                throw std::runtime_error(
                    "Falha copiando diretorio: " + src.string() + " : " + ec.message()
                );
            }

            fs::remove_all(to_extended_path(src), ec);
            if (ec) {
                throw std::runtime_error(
                    "Falha removendo diretorio origem: " + src.string() + " : " + ec.message()
                );
            }
        } else {
            fs::copy_file(
                to_extended_path(src),
                to_extended_path(dst),
                fs::copy_options::overwrite_existing,
                ec
            );
            if (ec) {
                throw std::runtime_error(
                    "Falha copiando arquivo: " + src.string() + " : " + ec.message()
                );
            }

            fs::remove(to_extended_path(src), ec);
            if (ec) {
                throw std::runtime_error(
                    "Falha removendo arquivo origem: " + src.string() + " : " + ec.message()
                );
            }
        }

        std::cout << "[>] Movido (via copy+remove): "
                << src << " -> " << dst << "\n";
    }


    void move_chipsec_artifacts(const fs::path& inputDir,
                                const std::string& inputFilename,
                                const fs::path& outputDir) {
        fs::path dirPath    = inputDir / (inputFilename + ".dir");
        fs::path uefiPrefix = inputDir / (inputFilename + ".UEFI.");

        // destino: outputs/chipsec_outputs
        fs::path chipsecOut = outputDir / "chipsec_outputs";
        fs::create_directories(chipsecOut);

        if (fs::exists(dirPath) && fs::is_directory(dirPath)) {
            move_path_best_effort(dirPath, chipsecOut / dirPath.filename());
        }

        for (const auto& entry : fs::directory_iterator(inputDir)) {
            fs::path p = entry.path();
            std::string name = p.filename().string();
            if (name.rfind(inputFilename + ".UEFI.", 0) == 0) {
                move_path_best_effort(p, chipsecOut / p.filename());
            }
        }
    }
    // ### fim metodos do ChipsecExtractor standalone ###
    // ##################################################
    
    // ##################################################
    // ####### metodos do UEFIExtract standalone ########
    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        return s;
    }

    static std::string trim_spaces(std::string s) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
            s.erase(s.begin());
        }
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
            s.pop_back();
        }
        return s;
    }

    // split simples para CSV com separador virgula, sem aspas aninhadas
    static std::vector<std::string> split_csv_line(const std::string& line) {
        std::vector<std::string> parts;
        std::string current;
        bool inQuotes = false;

        for (char c : line) {
            if (c == '"') {
                inQuotes = !inQuotes;
                continue;
            }
            if (c == ',' && !inQuotes) {
                parts.push_back(trim_spaces(current));
                current.clear();
            } else {
                current.push_back(c);
            }
        }
        if (!current.empty()) {
            parts.push_back(trim_spaces(current));
        }
        return parts;
    }

    // lê nomes de módulos do <firmware>.guids.csv
    std::vector<std::string> parse_module_names_from_csv(const fs::path& csvPath) {
        std::vector<std::string> modules;
        if (!fs::exists(csvPath)) {
            std::cerr << "[uefiextract] CSV de GUIDs nao encontrado: "
                      << csvPath << "\n";
            return modules;
        }

        std::ifstream f(csvPath);
        if (!f) {
            std::cerr << "[uefiextract] Falha ao abrir CSV: " << csvPath << "\n";
            return modules;
        }

        std::string line;
        bool isHeader = true;
        while (std::getline(f, line)) {
            line = trim_spaces(line);
            if (line.empty()) continue;

            auto cols = split_csv_line(line);
            if (cols.size() < 2) continue;

            // coluna 1: GUID, coluna 2: Name
            std::string name = trim_spaces(cols[1]);

            if (isHeader) {
                std::string low = to_lower(name);
                if (low.find("name") != std::string::npos) {
                    isHeader = false;
                    continue;
                }
                isHeader = false;
            }

            if (!name.empty()) {
                modules.push_back(name);
            }
        }
        std::cout << "[uefiextract] Modulos listados no CSV: "
                  << modules.size() << "\n";
        return modules;
    }


    // renomeia body.bin nas pastas PE32 image section para <Modulo>.efi
    void rename_bodies_using_index(const fs::path& dumpRoot,
                                   const std::vector<std::string>& modules) {
        if (!fs::exists(dumpRoot) || !fs::is_directory(dumpRoot)) {
            std::cerr << "[uefiextract] Dump root invalido para rename_bodies: "
                      << dumpRoot << "\n";
            return;
        }

        std::vector<fs::path> bodyFiles;

        for (auto& entry : fs::recursive_directory_iterator(dumpRoot)) {
            if (!entry.is_regular_file()) continue;
            if (entry.path().filename() != "body.bin") continue;

            std::string parentName = entry.path().parent_path().filename().string();
            std::string parentLower = to_lower(parentName);

            if (parentLower.find("pe32 image section") != std::string::npos) {
                bodyFiles.push_back(entry.path());
            }
        }

        std::cout << "[uefiextract] body.bin candidatos em PE32 image section: "
                  << bodyFiles.size() << "\n";

        size_t count = std::min(bodyFiles.size(), modules.size());
        for (size_t i = 0; i < count; ++i) {
            const auto& body = bodyFiles[i];
            std::string modName = modules[i];

            // sanitiza nome de modulo para virar filename
            for (char& c : modName) {
                if (c == '\"' || c == '*' || c == '?' || c == '<' ||
                    c == '>' || c == '|' || c == ':' || c == '\\' || c == '/') {
                    c = '_';
                }
            }

            fs::path newName = body.parent_path() / (modName + ".efi");
            std::error_code ec;
            fs::rename(body, newName, ec);
            if (ec) {
                std::cerr << "[uefiextract] Falha ao renomear "
                          << body << " -> " << newName
                          << "  " << ec.message() << "\n";
            } else {
                std::cout << "[uefiextract] body.bin renomeado para "
                          << newName << "\n";
            }
        }
    }

    // copia .efi do dump para destRoot sobrescrevendo
    size_t copy_efi_flat_overwrite(const std::vector<fs::path>& efiFiles,
                                   const fs::path& destRoot) {
        fs::create_directories(destRoot);
        size_t copied = 0;

        for (const auto& p : efiFiles) {
            if (!fs::exists(p) || !fs::is_regular_file(p)) {
                std::cerr << "[uefiextract] Ignorando arquivo inexistente ou invalido: "
                          << p << "\n";
                continue;
            }
            fs::path dest = destRoot / p.filename();
            std::error_code ec;
            fs::copy_file(p, dest, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                std::cerr << "[uefiextract] Erro ao copiar "
                          << p << " -> " << dest
                          << "  " << ec.message() << "\n";
                continue;
            }
            std::cout << "[uefiextract] Copiado "
                      << p << " -> " << dest << "\n";
            copied++;
        }

        return copied;
    }

    // move dump, csv, report para cfg.uefiExtractOutDir, usando move_path_best_effort
    void move_uefiextract_artifacts(const fs::path& inputDir,
                                    const std::string& inputFilename,
                                    const fs::path& uefiOutDir) {
        fs::create_directories(uefiOutDir);

        fs::path dumpDir   = inputDir / (inputFilename + ".dump");
        fs::path csvPath   = inputDir / (inputFilename + ".guids.csv");
        fs::path reportTxt = inputDir / (inputFilename + ".report.txt");

        if (fs::exists(dumpDir) && fs::is_directory(dumpDir)) {
            move_path_best_effort(dumpDir, uefiOutDir / dumpDir.filename());
        } else {
            std::cerr << "[uefiextract] Dump nao encontrado: "
                      << dumpDir << "\n";
        }

        if (fs::exists(csvPath)) {
            move_path_best_effort(csvPath, uefiOutDir / csvPath.filename());
        } else {
            std::cerr << "[uefiextract] CSV nao encontrado: "
                      << csvPath << "\n";
        }

        if (fs::exists(reportTxt)) {
            move_path_best_effort(reportTxt, uefiOutDir / reportTxt.filename());
        } else {
            std::cerr << "[uefiextract] Report TXT nao encontrado: "
                      << reportTxt << "\n";
        }
    }

        static void cleanupInputArtifacts(const Config& cfg) {
        fs::path inputDir = cfg.firmwarePath.parent_path();
        if (!fs::exists(inputDir) || !fs::is_directory(inputDir)) {
            return;
        }

        std::cout << "[cleanup] Limpando artefatos temporarios em: "
                  << inputDir << "\n";

        for (const auto& entry : fs::directory_iterator(inputDir)) {
            fs::path p = entry.path();
            std::string fname = p.filename().string();
            std::string ext   = p.extension().string();

            // preservar listas sensíveis
            if (fname == "BlackListGUIDs.txt" || fname == "BlackListStrings.txt") {
                continue;
            }

            bool shouldRemove = false;

            if (entry.is_directory()) {
                // casos tipo firmware.bin.dir e firmware.bin.dump
                if (fname.size() >= 4 && fname.substr(fname.size() - 4) == ".dir") {
                    shouldRemove = true;
                }
                if (fname.size() >= 5 && fname.substr(fname.size() - 5) == ".dump") {
                    shouldRemove = true;
                }
            } else {
                // arquivos normais
                if (ext == ".lst" || ext == ".json" || ext == ".csv" || ext == ".txt") {
                    shouldRemove = true;
                }
                // só por garantia, se alguém gerar .dir ou .dump como arquivo
                if (ext == ".dir" || ext == ".dump") {
                    shouldRemove = true;
                }
            }

            if (!shouldRemove) {
                continue;
            }

            std::error_code ec;
            if (entry.is_directory()) {
                fs::remove_all(p, ec);
            } else {
                fs::remove(p, ec);
            }

            if (ec) {
                std::cerr << "[cleanup] Falha ao apagar "
                          << p << " : " << ec.message() << "\n";
            } else {
                std::cout << "[cleanup] Removido: " << p << "\n";
            }
        }
    }

    // ##### fim metodos do UEFIExtract standalone ######
    // ##################################################
    
    // ##################################################
    // ######## metodos do PEAnalyzer standalone ########
    // Entropia de Shannon para bytes de seção
    static double shannon_entropy(const uint8_t* data, size_t n) {
        if (!data || n == 0) return 0.0;

        double freq[256] = {0.0};
        for (size_t i = 0; i < n; ++i) {
            freq[data[i]] += 1.0;
        }

        double H = 0.0;
        for (int i = 0; i < 256; ++i) {
            if (freq[i] == 0.0) continue;
            double p = freq[i] / static_cast<double>(n);
            H -= p * std::log2(p);
        }
        return H;
    }

#ifdef _WIN32
    // SHA 256 usando Windows CNG, igual ao standalone
    static std::vector<uint8_t> sha256_bytes(const uint8_t* data, size_t len) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0
        );
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptGetProperty(
            hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbHashObject,
            sizeof(cbHashObject),
            &cbData,
            0
        );
        if (status < 0) throw std::runtime_error("BCryptGetProperty OBJECT_LENGTH failed");

        status = BCryptGetProperty(
            hAlg,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&cbHash,
            sizeof(cbHash),
            &cbData,
            0
        );
        if (status < 0) throw std::runtime_error("BCryptGetProperty HASH_LENGTH failed");

        std::vector<uint8_t> hashObject(cbHashObject);
        std::vector<uint8_t> hash(cbHash);

        status = BCryptCreateHash(
            hAlg,
            &hHash,
            hashObject.data(),
            cbHashObject,
            NULL,
            0,
            0
        );
        if (status < 0) throw std::runtime_error("BCryptCreateHash failed");

        status = BCryptHashData(
            hHash,
            (PUCHAR)data,
            (ULONG)len,
            0
        );
        if (status < 0) throw std::runtime_error("BCryptHashData failed");

        status = BCryptFinishHash(
            hHash,
            hash.data(),
            cbHash,
            0
        );
        if (status < 0) throw std::runtime_error("BCryptFinishHash failed");

        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);

        return hash;
    }
#else
    static std::vector<uint8_t> sha256_bytes(const uint8_t* data, size_t len) {
        throw std::runtime_error("sha256_bytes not implemented on non Windows");
    }
#endif

    static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill('0');
        for (auto b : v) {
            oss << std::setw(2) << static_cast<unsigned int>(b);
        }
        return oss.str();
    }

    static std::string machine_to_str(WORD m) {
        switch (m) {
            case IMAGE_FILE_MACHINE_I386:  return "I386";
            case IMAGE_FILE_MACHINE_AMD64: return "AMD64";
            case IMAGE_FILE_MACHINE_ARM:   return "ARM";
            case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
            default: {
                std::ostringstream oss;
                oss << "0x" << std::hex << std::uppercase << m;
                return oss.str();
            }
        }
    }

    static std::string subsystem_to_str(WORD s) {
        switch (s) {
            case IMAGE_SUBSYSTEM_EFI_APPLICATION:          return "EFI_APPLICATION";
            case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:  return "EFI_BOOT_SERVICE_DRIVER";
            case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:       return "EFI_RUNTIME_DRIVER";
            case IMAGE_SUBSYSTEM_EFI_ROM:                  return "EFI_ROM";
            default: {
                std::ostringstream oss;
                oss << "0x" << std::hex << std::uppercase << s;
                return oss.str();
            }
        }
    }

    // Map: lower(nomeModulo) -> lista de GUIDs
    static std::unordered_map<std::string, std::vector<std::string>>
    load_guid_map(const fs::path& csvPath) {
        std::unordered_map<std::string, std::vector<std::string>> m;

        std::ifstream in(csvPath);
        if (!in) {
            std::cerr << "[!] Aviso: nao consegui abrir CSV de GUIDs: "
                      << csvPath << "\n";
            return m;
        }

        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;

            auto cols = split_csv_line(line);
            if (cols.size() < 2) continue;

            // formato esperado: GUID,Name,...
            std::string guid = trim_spaces(cols[0]);
            std::string name = trim_spaces(cols[1]);

            if (guid.empty() || name.empty()) continue;

            std::string key = to_lower(name);
            m[key].push_back(guid);
        }

        std::cout << "[GUID] Linhas carregadas do CSV: " << m.size() << "\n";
        return m;
    }

    // procura GUID(s) para o módulo com base no nome do .efi
    static std::vector<std::string>
    find_guids_for_module(const std::unordered_map<std::string, std::vector<std::string>>& map,
                          const std::string& moduleStemLower) {
        std::vector<std::string> out;

        auto it = map.find(moduleStemLower);
        if (it != map.end()) return it->second;

        for (const auto& kv : map) {
            if (kv.first.find(moduleStemLower) != std::string::npos) {
                out.insert(out.end(), kv.second.begin(), kv.second.end());
            }
        }
        return out;
    }

    static PeInfo analyze_pe(const fs::path& file) {
        PeInfo info;

        std::ifstream in(file, std::ios::binary);
        if (!in) {
            info.error = "cannot open";
            return info;
        }

        in.seekg(0, std::ios::end);
        size_t fsize = static_cast<size_t>(in.tellg());
        in.seekg(0, std::ios::beg);

        if (fsize == 0) {
            info.error = "empty file";
            return info;
        }

        std::vector<uint8_t> buf(fsize);
        in.read(reinterpret_cast<char*>(buf.data()), fsize);

        try {
            info.file_sha256_hex = bytes_to_hex(sha256_bytes(buf.data(), buf.size()));
        } catch (...) {
            info.file_sha256_hex = "<sha256-error>";
        }

        if (fsize < sizeof(IMAGE_DOS_HEADER)) {
            info.error = "too small for DOS header";
            return info;
        }

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            info.error = "missing MZ";
            return info;
        }

        if (dos->e_lfanew <= 0 ||
            static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > fsize) {
            info.error = "invalid e_lfanew";
            return info;
        }

        auto* ntSig = reinterpret_cast<const DWORD*>(buf.data() + dos->e_lfanew);
        if (*ntSig != IMAGE_NT_SIGNATURE) {
            info.error = "missing PE signature";
            return info;
        }

        auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buf.data() + dos->e_lfanew + sizeof(DWORD));
        info.machine = fileHdr->Machine;
        info.characteristics = fileHdr->Characteristics;
        info.numSections = fileHdr->NumberOfSections;

        const uint8_t* optBase = reinterpret_cast<const uint8_t*>(fileHdr) + sizeof(IMAGE_FILE_HEADER);
        WORD magic = *reinterpret_cast<const WORD*>(optBase);

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            info.is64 = true;
            auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optBase);
            info.entryRva = opt->AddressOfEntryPoint;
            info.imageBase = opt->ImageBase;
            info.sizeOfImage = opt->SizeOfImage;
            info.sizeOfHeaders = opt->SizeOfHeaders;
            info.subsystem = opt->Subsystem;

            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
            auto* sec = IMAGE_FIRST_SECTION(nt);

            for (unsigned i = 0; i < fileHdr->NumberOfSections; ++i, ++sec) {
                SectionInfo si;
                char name[9] = {0};
                std::memcpy(name, sec->Name, 8);
                si.name = name;

                si.rva = sec->VirtualAddress;
                si.vsize = sec->Misc.VirtualSize;
                si.rawPtr = sec->PointerToRawData;
                si.rawSize = sec->SizeOfRawData;

                size_t rp = si.rawPtr;
                size_t rs = si.rawSize;
                if (rp < fsize && rp + rs <= fsize && rs > 0) {
                    const uint8_t* sdata = buf.data() + rp;
                    si.entropy = shannon_entropy(sdata, rs);
                    try {
                        si.sha256_hex = bytes_to_hex(sha256_bytes(sdata, rs));
                    } catch (...) {
                        si.sha256_hex = "<sha256-error>";
                    }
                } else {
                    si.entropy = 0.0;
                    si.sha256_hex = "<no-raw>";
                }
                info.sections.push_back(si);
            }
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            info.is64 = false;
            auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optBase);
            info.entryRva = opt->AddressOfEntryPoint;
            info.imageBase = opt->ImageBase;
            info.sizeOfImage = opt->SizeOfImage;
            info.sizeOfHeaders = opt->SizeOfHeaders;
            info.subsystem = opt->Subsystem;

            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf.data() + dos->e_lfanew);
            auto* sec = IMAGE_FIRST_SECTION(nt);

            for (unsigned i = 0; i < fileHdr->NumberOfSections; ++i, ++sec) {
                SectionInfo si;
                char name[9] = {0};
                std::memcpy(name, sec->Name, 8);
                si.name = name;

                si.rva = sec->VirtualAddress;
                si.vsize = sec->Misc.VirtualSize;
                si.rawPtr = sec->PointerToRawData;
                si.rawSize = sec->SizeOfRawData;

                size_t rp = si.rawPtr;
                size_t rs = si.rawSize;
                if (rp < fsize && rp + rs <= fsize && rs > 0) {
                    const uint8_t* sdata = buf.data() + rp;
                    si.entropy = shannon_entropy(sdata, rs);
                    try {
                        si.sha256_hex = bytes_to_hex(sha256_bytes(sdata, rs));
                    } catch (...) {
                        si.sha256_hex = "<sha256-error>";
                    }
                } else {
                    si.entropy = 0.0;
                    si.sha256_hex = "<no-raw>";
                }
                info.sections.push_back(si);
            }
        } else {
            info.error = "unknown optional header magic";
            return info;
        }

        info.is_pe = true;
        return info;
    }
    // ###### fim metodos do PEAnalyzer standalone ######
    // ##################################################

    // ##################################################
    // ########## metodos do Qiling standalone ##########
    // --------- helper para rodar comando com output streaming (para Qiling) ---------
    static int run_command_streaming(const std::string& cmd) {
        std::array<char, 4096> buffer{};
    #ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
    #else
        FILE* pipe = popen(cmd.c_str(), "r");
    #endif
        if (!pipe) {
            std::cerr << "[qiling] Falha ao executar comando via popen.\n";
            return -1;
        }
        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
            std::cout << buffer.data();
        }
    #ifdef _WIN32
        int rc = _pclose(pipe);
    #else
        int rc = pclose(pipe);
    #endif
        return rc;
    }

    // sanitiza nome de pasta para logs por modulo
    static std::string sanitize_folder_name(std::string s) {
        for (char& c : s) {
            if (c == '\\' || c == '/' || c == ':' || c == '*' ||
                c == '?'  || c == '"' || c == '<' || c == '>' || c == '|') {
                c = '_';
            }
        }
        return s;
    }
    // ######## fim metodos do Qiling standalone ########
    // ##################################################

    // =====================================================================
    // ThreadPool
    // =====================================================================

    ThreadPool::ThreadPool(size_t numThreads) {
        for (size_t i = 0; i < numThreads; ++i) {
            m_workers.emplace_back([this]() { workerLoop(); });
        }
    }

    ThreadPool::~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_stop = true;
        }
        m_cv.notify_all();
        for (auto& t : m_workers) {
            t.join();
        }
    }

    void ThreadPool::enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_tasks.push(std::move(task));
        }
        m_cv.notify_one();
    }

    void ThreadPool::workerLoop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this]() {
                    return m_stop || !m_tasks.empty();
                });
                if (m_stop && m_tasks.empty())
                    return;
                task = std::move(m_tasks.front());
                m_tasks.pop();
            }
            try {
                task();
            } catch (const std::exception& e) {
                std::cerr << "[ThreadPool] excecao: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[ThreadPool] excecao desconhecida\n";
            }
        }
    }

    // =====================================================================
    // ChipsecExtractor
    // =====================================================================

    bool ChipsecExtractor::extract(const Config& cfg,
                                std::vector<fs::path>& outModules) {
        try {
            fs::path inputPath     = cfg.firmwarePath;
            fs::path inputDir      = inputPath.parent_path();
            std::string inputName  = inputPath.filename().string();
            fs::path outputDirPath = cfg.workspaceDir;

            if (!fs::exists(inputPath)) {
                std::cerr << "[chipsec] input_file_path nao existe: "
                        << inputPath << "\n";
                return false;
            }

            fs::path chipsecUtil = cfg.chipsecScript;

            std::string cmd = "python \"" + chipsecUtil.string() +
                            "\" uefi decode \"" + inputPath.string() + "\"";

            std::cout << "[chipsec] Executando CHIPSEC...\n";
            int rc = runCommand(cmd);
            if (rc != 0) {
                std::cerr << "[chipsec] CHIPSEC terminou com erro. Exit code: "
                        << rc << "\n";
            }

            fs::path dirPath     = inputDir / (inputName + ".dir");
            fs::path efiDestRoot = cfg.modulesDir; // outputs/modules

            std::cout << "[chipsec] Listando .efi em: " << dirPath << "\n";
            auto efiFiles = list_efi_strict_via_powershell(dirPath);
            std::cout << "[chipsec] Total de .efi encontrados: "
                    << efiFiles.size() << "\n";

            size_t copied = copy_efi_flat_from_list(efiFiles, efiDestRoot);
            std::cout << "[chipsec] Total copiado para " << efiDestRoot
                    << ": " << copied << "\n";

            std::cout << "[chipsec] Movendo artefatos CHIPSEC...\n";
            move_chipsec_artifacts(inputDir, inputName, outputDirPath);

            // atualiza lista de módulos
            outModules.clear();
            for (const auto& entry : fs::directory_iterator(efiDestRoot)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().extension() == ".efi") {
                    outModules.push_back(entry.path());
                }
            }

            return copied > 0;
        } catch (const std::exception& e) {
            std::cerr << "[chipsec] EXCEPTION: " << e.what() << "\n";
            return false;
        }
    }


    // =====================================================================
    // UefiExtractExtractor 
    // =====================================================================

    bool UefiExtractExtractor::extract(const Config& cfg,
                                       std::vector<fs::path>& outModules) {
        try {
            fs::path inputPath = cfg.firmwarePath;
            fs::path inputDir  = inputPath.parent_path();
            std::string inputName = inputPath.filename().string();

            if (!fs::exists(inputPath)) {
                std::cerr << "[uefiextract] Firmware nao existe: "
                          << inputPath << "\n";
                return false;
            }
            if (!fs::exists(cfg.uefiExtractExe)) {
                std::cerr << "[uefiextract] Nao encontrei UEFIExtract.exe em: "
                          << cfg.uefiExtractExe << "\n";
                return false;
            }

            std::cout << "[uefiextract] Executando UEFIExtract...\n";

            // mesmo estilo que seu standalone: chama "UEFIExtract.exe <firmware> all"
            std::string cmd =
                "cmd /C \"\"" +
                cfg.uefiExtractExe.string() +
                "\" \"" +
                inputPath.string() +
                "\" all\"";

            int rc = runCommand(cmd);
            if (rc != 0) {
                std::cerr << "[uefiextract] UEFIExtract terminou com erro. Exit code: "
                          << rc << "\n";
            }

            // dump e csv gerados ao lado do firmware
            fs::path dumpDir = inputDir / (inputName + ".dump");
            fs::path csvPath = inputDir / (inputName + ".guids.csv");

            // 1) parsear nomes de modulos do CSV
            auto modules = parse_module_names_from_csv(csvPath);

            // 2) renomear body.bin para <Modulo>.efi
            if (fs::exists(dumpDir) && fs::is_directory(dumpDir)) {
                rename_bodies_using_index(dumpDir, modules);

                // 3) listar .efi no dump e copiar para cfg.modulesDir sobrescrevendo
                auto efiFiles = list_efi_strict_via_powershell(dumpDir);
                std::cout << "[uefiextract] .efi encontrados no dump: "
                          << efiFiles.size() << "\n";

                size_t copied = copy_efi_flat_overwrite(efiFiles, cfg.modulesDir);
                std::cout << "[uefiextract] .efi copiados para "
                          << cfg.modulesDir << ": " << copied << "\n";
            } else {
                std::cerr << "[uefiextract] Diretorio dump nao encontrado: "
                          << dumpDir << "\n";
            }

            // 4) mover dump/csv/report para cfg.uefiExtractOutDir
            move_uefiextract_artifacts(inputDir, inputName, cfg.uefiExtractOutDir);

            // 5) atualizar lista final de modulos em modulesDir
            outModules.clear();
            for (const auto& entry : fs::directory_iterator(cfg.modulesDir)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().extension() == ".efi") {
                    outModules.push_back(entry.path());
                }
            }

            return !outModules.empty();
        } catch (const std::exception& e) {
            std::cerr << "[uefiextract] EXCEPTION: " << e.what() << "\n";
            return false;
        }
    }


    // =====================================================================
    // PeCoffAnalyzer
    // =====================================================================

    // Helpers internos para leitura de arquivo
    static bool readFileBytes(const fs::path& p, std::vector<uint8_t>& out) {
        std::ifstream ifs(p, std::ios::binary);
        if (!ifs)
            return false;
        ifs.seekg(0, std::ios::end);
        std::streampos size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        out.resize(static_cast<size_t>(size));
        if (!out.empty())
            ifs.read(reinterpret_cast<char*>(out.data()), size);
        return true;
    }


    void PeCoffAnalyzer::analyzeModules(const Config& cfg,
                                    const std::vector<fs::path>& modules,
                                    std::vector<ModuleRecord>& outRecords) const {
        outRecords.clear();

        // Garante que sempre teremos uma lista de modulos
        std::vector<fs::path> effectiveModules = modules;
        if (effectiveModules.empty()) {
            if (fs::exists(cfg.modulesDir) && fs::is_directory(cfg.modulesDir)) {
                for (const auto& entry : fs::directory_iterator(cfg.modulesDir)) {
                    if (entry.is_regular_file() &&
                        entry.path().extension() == ".efi") {
                        effectiveModules.push_back(entry.path());
                    }
                }
            }
        }

        if (effectiveModules.empty()) {
            std::cout << "[pe] Nenhum modulo .efi para analisar\n";
            return;
        }

        std::cout << "[pe] Modulos para analise: "
                << effectiveModules.size() << "\n";

        // CSV de GUIDs produzido pela UEFIExtract, ja movido para cfg.uefiExtractOutDir
        std::string fwName = cfg.firmwarePath.filename().string();
        fs::path guidCsv = cfg.uefiExtractOutDir / (fwName + ".guids.csv");
        auto guidMap = load_guid_map(guidCsv);

        // pasta de log
        fs::path logDir  = cfg.reportsDir / "pe_module_information";
        fs::create_directories(logDir);
        fs::path logPath = logDir / "pe_modules_analysis.log";

        std::ofstream log(logPath, std::ios::out | std::ios::binary);
        if (!log) {
            std::cerr << "[pe] Nao consegui criar log em: "
                    << logPath << "\n";
        } else {
            log << "[*] PE/COFF Analysis Log\n";
            log << "[*] Modules dir: " << cfg.modulesDir.string() << "\n";
            log << "[*] GUID CSV: " << guidCsv.string() << "\n\n";
        }

        size_t total   = 0;
        size_t pe_ok   = 0;
        size_t pe_fail = 0;

        for (const auto& mpath : effectiveModules) {
            total++;

            ModuleRecord rec;
            rec.path = mpath;

            std::error_code ec;
            rec.fileSize = fs::file_size(mpath, ec);
            if (ec) rec.fileSize = 0;

            PeInfo info = analyze_pe(mpath);

            // associa GUIDs
            std::string stemLower = to_lower(mpath.stem().string());
            auto guids = find_guids_for_module(guidMap, stemLower);
            info.related_guids = guids;

            if (!info.is_pe || !info.error.empty()) {
                pe_fail++;
            } else {
                pe_ok++;
            }

            if (log) {
                log << "-------------------------------------------------------------------------------\n";
                log << "[MODULE] " << mpath.filename().string() << "\n";
                log << "  Path: " << mpath.string() << "\n";
                log << "  Size: " << rec.fileSize << " bytes\n";

                if (!info.error.empty()) {
                    log << "  PE: INVALID (" << info.error << ")\n\n";
                } else {
                    log << "  PE: OK (" << (info.is64 ? "PE32+" : "PE32") << "\n";
                    log << "  Machine: " << machine_to_str(info.machine) << "\n";
                    log << "  Subsystem: " << subsystem_to_str(info.subsystem) << "\n";
                    log << "  EntryRVA: 0x" << std::hex << std::uppercase
                        << info.entryRva << std::dec << "\n";
                    log << "  ImageBase: 0x" << std::hex << std::uppercase
                        << info.imageBase << std::dec << "\n";
                    log << "  SizeOfImage: " << info.sizeOfImage << "\n";
                    log << "  SizeOfHeaders: " << info.sizeOfHeaders << "\n";
                    log << "  Sections: " << info.sections.size() << "\n";
                    log << "  File SHA256: " << info.file_sha256_hex << "\n";

                    if (!guids.empty()) {
                        for (const auto& g : guids) {
                            log << "  [GUID] " << g << "\n";
                        }
                    } else {
                        log << "  [GUID] <not found in csv>\n";
                    }

                    for (const auto& s : info.sections) {
                        log << "    [SECTION]\n";
                        log << "      Name: " << s.name << "\n";
                        log << "      RVA: 0x" << std::hex << std::uppercase
                            << s.rva << std::dec << "\n";
                        log << "      VirtualSize: " << s.vsize << "\n";
                        log << "      RawPtr: 0x" << std::hex << std::uppercase
                            << s.rawPtr << std::dec << "\n";
                        log << "      RawSize: " << s.rawSize << "\n";
                        log << "      Entropy: " << std::fixed
                            << std::setprecision(4) << s.entropy << "\n";
                        log << "      SHA256: " << s.sha256_hex << "\n";
                    }
                    log << "\n";
                }
            }

            rec.pe = std::move(info);
            outRecords.push_back(std::move(rec));
        }

        if (log) {
            log << "================================================================================\n";
            log << "[SUMMARY]\n";
            log << "Total .efi: " << total << "\n";
            log << "Valid PE: " << pe_ok << "\n";
            log << "Invalid/Fail: " << pe_fail << "\n";
            log.close();
            std::cout << "[pe] Log gerado em: " << logPath << "\n";
        }
    }


    // =====================================================================
    // StringExtractor
    // =====================================================================

    static bool isPrintableAscii(unsigned char c) {
        return c >= 0x20 && c <= 0x7e;
    }

    void StringExtractor::extractStrings(const Config& cfg, ModuleRecord& mod) {
        mod.strings.clear();

        std::vector<uint8_t> data;
        if (!readFileBytes(mod.path, data)) {
            std::cerr << "[strings] Falha ao ler modulo: "
                    << mod.path << "\n";
            return;
        }

        // ASCII
        {
            size_t i = 0;
            while (i < data.size()) {
                size_t start = i;
                while (i < data.size() && isPrintableAscii(data[i])) {
                    ++i;
                }
                size_t len = i - start;
                if (len >= static_cast<size_t>(cfg.minAsciiLen)) {
                    StringEntry e;
                    e.offset = static_cast<uint64_t>(start);
                    e.value.assign(
                        reinterpret_cast<const char*>(&data[start]),
                        len
                    );
                    e.isUtf16 = false;
                    mod.strings.push_back(std::move(e));
                }
                while (i < data.size() && !isPrintableAscii(data[i])) {
                    ++i;
                }
            }
        }

        // UTF 16 LE simples
        {
            size_t i = 0;
            while (i + 1 < data.size()) {
                size_t start = i;
                bool any = false;
                while (i + 1 < data.size()) {
                    uint16_t ch = static_cast<uint16_t>(data[i]) |
                                (static_cast<uint16_t>(data[i + 1]) << 8);
                    if (ch >= 0x20 && ch <= 0x7e) {
                        any = true;
                        i += 2;
                    } else {
                        break;
                    }
                }
                size_t bytesLen = i - start;
                size_t charsLen = bytesLen / 2;
                if (any && charsLen >= static_cast<size_t>(cfg.minUtf16Len)) {
                    std::u16string u16;
                    u16.resize(charsLen);
                    for (size_t k = 0; k < charsLen; ++k) {
                        u16[k] = static_cast<char16_t>(
                            data[start + 2 * k] |
                            (data[start + 2 * k + 1] << 8)
                        );
                    }
                    // conversao simples para UTF 8
                    std::string utf8;
                    utf8.reserve(charsLen);
                    for (char16_t ch : u16) {
                        if (ch <= 0x7f)
                            utf8.push_back(static_cast<char>(ch));
                        else
                            utf8.push_back('?');
                    }

                    StringEntry e;
                    e.offset = static_cast<uint64_t>(start);
                    e.value  = std::move(utf8);
                    e.isUtf16 = true;
                    mod.strings.push_back(std::move(e));
                }
                i += 2;
            }
        }

        // Persistir strings em arquivo na pasta stringsOutDir
        try {
            if (!fs::exists(cfg.stringsOutDir)) {
                fs::create_directories(cfg.stringsOutDir);
            }

            fs::path outPath = cfg.stringsOutDir /
                            (mod.path.filename().string() + ".strings.txt");

            std::ofstream out(outPath, std::ios::out | std::ios::binary);
            if (!out) {
                std::cerr << "[strings] Nao foi possivel criar arquivo de strings: "
                        << outPath << "\n";
                return;
            }

            out << "Module: "   << mod.path.filename().string() << "\n";
            out << "FullPath: " << mod.path.string() << "\n";
            out << "TotalStrings: " << mod.strings.size() << "\n\n";

            for (const auto& s : mod.strings) {
                out << (s.isUtf16 ? "UTF16" : "ASCII")
                    << "\t0x" << std::hex << s.offset << std::dec
                    << "\t" << s.value << "\n";
            }

            std::cout << "[strings] Arquivo gerado: "
                    << outPath << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[strings] EXCEPTION ao salvar arquivo: "
                    << e.what() << "\n";
        }
    }

    // =====================================================================
    // SensitiveMatcher
    // =====================================================================

    void SensitiveMatcher::loadPatterns(const Config& cfg) {
        m_stringPatterns.clear();
        m_guidPatterns.clear();

        // Strings sensiveis
        if (!cfg.sensitiveStringsFile.empty()) {
            std::ifstream f(cfg.sensitiveStringsFile);
            if (!f) {
                std::cerr << "[sensitive] Aviso: nao foi possivel abrir "
                        << cfg.sensitiveStringsFile << "\n";
            } else {
                std::string line;
                while (std::getline(f, line)) {
                    line = trim_spaces(line);
                    if (line.empty()) continue;
                    if (!line.empty() && line[0] == '#') continue;
                    m_stringPatterns.push_back(line);
                }
                std::cout << "[sensitive] Padrões de STRING carregados: "
                        << m_stringPatterns.size() << "\n";
            }
        }

        // GUIDs sensiveis
        if (!cfg.sensitiveGuidsFile.empty()) {
            std::ifstream f(cfg.sensitiveGuidsFile);
            if (!f) {
                std::cerr << "[sensitive] Aviso: nao foi possivel abrir "
                        << cfg.sensitiveGuidsFile << "\n";
            } else {
                std::string line;
                while (std::getline(f, line)) {
                    line = trim_spaces(line);
                    if (line.empty()) continue;
                    if (!line.empty() && line[0] == '#') continue;
                    m_guidPatterns.push_back(line);
                }
                std::cout << "[sensitive] Padrões de GUID carregados: "
                        << m_guidPatterns.size() << "\n";
            }
        }
    }

    void SensitiveMatcher::run(const Config& cfg, ModuleRecord& mod) {
        mod.sensitiveMatches.clear();

        if (m_stringPatterns.empty() && m_guidPatterns.empty()) {
            return;
        }

        // 1. Match de STRINGS sensiveis nas strings extraidas
        for (const auto& s : mod.strings) {
            std::string sLow = to_lower(s.value);

            // padrões de string
            for (const auto& pat : m_stringPatterns) {
                std::string pLow = to_lower(pat);
                if (sLow.find(pLow) != std::string::npos) {
                    SensitiveMatch m;
                    m.pattern = pat;
                    m.offset  = s.offset;
                    m.isUtf16 = s.isUtf16;
                    m.isGuid  = false;
                    mod.sensitiveMatches.push_back(std::move(m));
                }
            }

            // padrões de GUID nas strings
            for (const auto& pat : m_guidPatterns) {
                std::string pLow = to_lower(pat);
                if (sLow.find(pLow) != std::string::npos) {
                    SensitiveMatch m;
                    m.pattern = pat;
                    m.offset  = s.offset;
                    m.isUtf16 = s.isUtf16;
                    m.isGuid  = true;
                    mod.sensitiveMatches.push_back(std::move(m));
                }
            }
        }

        // 2. Match de GUIDs sensiveis contra GUIDs do modulo (UEFIExtract)
        if (!m_guidPatterns.empty() && !mod.pe.related_guids.empty()) {
            for (const auto& g : mod.pe.related_guids) {
                std::string gLow = to_lower(g);
                for (const auto& pat : m_guidPatterns) {
                    std::string pLow = to_lower(pat);
                    if (gLow.find(pLow) != std::string::npos) {
                        SensitiveMatch m;
                        m.pattern = g;              // ou pat, se preferir o padrão
                        m.offset  = 0;              // GUID vindo da lista, sem offset exato
                        m.isUtf16 = false;
                        m.isGuid  = true;
                        mod.sensitiveMatches.push_back(std::move(m));
                    }
                }
            }
        }

        // 3. Persistir arquivo em sensitiveOutDir
        try {
            if (!fs::exists(cfg.sensitiveOutDir)) {
                fs::create_directories(cfg.sensitiveOutDir);
            }

            fs::path outPath = cfg.sensitiveOutDir /
                            (mod.path.filename().string() + ".sensitive.txt");

            std::ofstream out(outPath, std::ios::out | std::ios::binary);
            if (!out) {
                std::cerr << "[sensitive] Nao foi possivel criar arquivo: "
                        << outPath << "\n";
                return;
            }

            out << "Module: " << mod.path.filename().string() << "\n";
            out << "FullPath: " << mod.path.string() << "\n";
            out << "Matches: " << mod.sensitiveMatches.size() << "\n\n";

            for (const auto& m : mod.sensitiveMatches) {
                out << (m.isGuid ? "GUID" : "STRING") << "\t"
                    << (m.isUtf16 ? "UTF16" : "ASCII") << "\t"
                    << "0x" << std::hex << m.offset << std::dec << "\t"
                    << m.pattern << "\n";
            }

            std::cout << "[sensitive] Arquivo gerado: "
                    << outPath << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[sensitive] EXCEPTION ao salvar arquivo: "
                    << e.what() << "\n";
        }
    }


    // =====================================================================
    // QilingExecutor
    // =====================================================================
    ExecutionStatus QilingExecutor::executeModule(const Config& cfg, const fs::path& modulePath) {
        ExecutionStatus st;

        if (!cfg.enableQiling) {
            st.status = ExecutionStatusKind::NotRun;
            std::cout << "[qiling] Skipping, Qiling disabled for module "
                    << modulePath.filename().string() << "\n";
            return st;
        }

        // Verifica se o script existe
        if (!fs::exists(cfg.qilingScript)) {
            std::cerr << "[qiling] ERRO: qilingScript nao encontrado em "
                    << cfg.qilingScript << "\n";
            st.status   = ExecutionStatusKind::Error;
            st.exitCode = -1;
            st.shortLog = "qilingScript not found";
            return st;
        }

        // pasta raiz de logs (outputs/qiling_logs)
        fs::create_directories(cfg.qilingLogsDir);

        // pasta especifica para este modulo: qiling_logs/<nome_sanitizado_do_modulo>
        std::string moduleName   = modulePath.filename().string();
        std::string moduleFolder = sanitize_folder_name(modulePath.stem().string());
        fs::path perModuleLogDir = cfg.qilingLogsDir / moduleFolder;
        fs::create_directories(perModuleLogDir);

        // comando python no mesmo formato do runner standalone
        std::ostringstream cmd;
        cmd << "py -3.13 "
            << "\"" << cfg.qilingScript.string() << "\" "
            << "--diretorio_de_modulos "
            << "\"" << cfg.modulesDir.string() << "\" "
            << "--modulo "
            << "\"" << moduleName << "\" "
            << "--timeout " << cfg.qilingTimeoutSec << " "
            << "--diretorio_saida "
            << "\"" << perModuleLogDir.string() << "\"";

        std::string cmdStr = cmd.str();
        std::cout << "[qiling] Executando para modulo "
                << moduleName << ":\n"
                << "  " << cmdStr << "\n";

        // Usa system simples para debug, sem streaming
        int ret = runCommand(cmdStr);
        st.exitCode = ret;

        if (ret == 0) {
            st.status  = ExecutionStatusKind::Success;
            st.shortLog = "Execution ok";
        } else {
            st.status   = ExecutionStatusKind::Error;
            st.shortLog = "Execution failed, code " + std::to_string(ret);
        }

        // aponta para a pasta onde o script python deve ter gravado os logs
        st.logFileOnDisk = perModuleLogDir;
        return st;
    }


    // =====================================================================
    // ManifestDAO
    // =====================================================================

    void ManifestDAO::save(const Config& cfg, const Manifest& manifest) {
        fs::create_directories(cfg.workspaceDir);
        std::ofstream out(cfg.manifestPath);
        if (!out) {
            std::cerr << "[!] Nao foi possivel abrir manifest.json para escrita\n";
            return;
        }

        out << "{\n";
        out << "  \"toolName\": \"" << manifest.toolName << "\",\n";
        out << "  \"toolVersion\": \"" << manifest.toolVersion << "\",\n";
        out << "  \"firmwarePath\": \"" << manifest.firmwarePath.string() << "\",\n";
        out << "  \"modules\": [\n";

        for (size_t i = 0; i < manifest.modules.size(); ++i) {
            const auto& m = manifest.modules[i];
            out << "    {\n";
            out << "      \"path\": \"" << m.path.string() << "\",\n";
            out << "      \"fileSize\": " << m.fileSize << ",\n";
            out << "      \"pe\": {\n";
            out << "        \"isValidPe\": " << (m.pe.is_pe ? "true" : "false") << ",\n";
            out << "        \"fileSha256\": \"" << m.pe.file_sha256_hex  << "\",\n";
            out << "        \"sections\": [\n";
            for (size_t j = 0; j < m.pe.sections.size(); ++j) {
                const auto& s = m.pe.sections[j];
                out << "          {\n";
                out << "            \"name\": \"" << s.name << "\",\n";
                out << "            \"virtualAddress\": " << s.rva << ",\n";
                out << "            \"virtualSize\": " << s.vsize << ",\n";
                out << "            \"rawOffset\": " << s.rawPtr << ",\n";
                out << "            \"rawSize\": " << s.rawSize << ",\n";
                out << "            \"entropy\": " << std::fixed << std::setprecision(4) << s.entropy << ",\n";
                out << "            \"sha256\": \"" << s.sha256_hex << "\"\n";
                out << "          }" << (j + 1 < m.pe.sections.size() ? "," : "") << "\n";
            }
            out << "        ]\n";
            out << "      },\n";

            out << "      \"strings\": [\n";
            for (size_t j = 0; j < m.strings.size(); ++j) {
                const auto& s = m.strings[j];
                out << "        {\n";
                out << "          \"offset\": " << s.offset << ",\n";
                out << "          \"value\": \"" << s.value << "\",\n";
                out << "          \"isUtf16\": " << (s.isUtf16 ? "true" : "false") << "\n";
                out << "        }" << (j + 1 < m.strings.size() ? "," : "") << "\n";
            }
            out << "      ],\n";

            out << "      \"sensitiveMatches\": [\n";
            for (size_t j = 0; j < m.sensitiveMatches.size(); ++j) {
                const auto& sm = m.sensitiveMatches[j];
                out << "        {\n";
                out << "          \"pattern\": \"" << sm.pattern << "\",\n";
                out << "          \"offset\": " << sm.offset << ",\n";
                out << "          \"isUtf16\": " << (sm.isUtf16 ? "true" : "false") << ",\n";
                out << "          \"isGuid\": " << (sm.isGuid ? "true" : "false") << "\n";
                out << "        }" << (j + 1 < m.sensitiveMatches.size() ? "," : "") << "\n";
            }
            out << "      ],\n";

            out << "      \"executionStatus\": {\n";
            out << "        \"status\": ";
            switch (m.execStatus.status) {
            case ExecutionStatusKind::NotRun: out << "\"NotRun\""; break;
            case ExecutionStatusKind::Success: out << "\"Success\""; break;
            case ExecutionStatusKind::Error: out << "\"Error\""; break;
            case ExecutionStatusKind::Timeout: out << "\"Timeout\""; break;
            }
            out << ",\n";
            out << "        \"exitCode\": " << m.execStatus.exitCode << ",\n";
            out << "        \"shortLog\": \"" << m.execStatus.shortLog << "\",\n";
            out << "        \"logFile\": \"" << m.execStatus.logFileOnDisk.string() << "\"\n";
            out << "      }\n";

            out << "    }" << (i + 1 < manifest.modules.size() ? "," : "") << "\n";
        }

        out << "  ]\n";
        out << "}\n";
    }

    // =====================================================================
    // ReportDAO
    // =====================================================================

    void ReportDAO::exportReports(const Config& cfg, const Manifest& manifest) {
        fs::create_directories(cfg.reportsDir);

        // CSV simples com resumo
        {
            std::ofstream csv(cfg.reportsDir / "modules_summary.csv");
            csv << "path,fileSize,isValidPe,fileSha256,totalStrings,totalSensitive\n";
            for (const auto& m : manifest.modules) {
                csv << "\"" << m.path.string() << "\","
                    << m.fileSize << ","
                    << (m.pe.is_pe ? "1" : "0") << ","
                    << "\"" << m.pe.file_sha256_hex  << "\","
                    << m.strings.size() << ","
                    << m.sensitiveMatches.size()
                    << "\n";
            }
        }

        // TXT simples com uma listagem mais legivel
        {
            std::ofstream txt(cfg.reportsDir / "modules_report.txt");
            for (const auto& m : manifest.modules) {
                txt << "Modulo: " << m.path << "\n";
                txt << "  Tamanho: " << m.fileSize << " bytes\n";
                txt << "  SHA256: " << m.pe.file_sha256_hex  << "\n";
                txt << "  Strings: " << m.strings.size()
                    << "  Sensitivas: " << m.sensitiveMatches.size() << "\n";
                txt << "  Execucao: ";
                switch (m.execStatus.status) {
                case ExecutionStatusKind::NotRun: txt << "Nao executado"; break;
                case ExecutionStatusKind::Success: txt << "Sucesso"; break;
                case ExecutionStatusKind::Error: txt << "Erro"; break;
                case ExecutionStatusKind::Timeout: txt << "Timeout"; break;
                }
                txt << "  exitCode=" << m.execStatus.exitCode << "\n\n";
            }
        }
    }

    // =====================================================================
    // BiosInspectorApp
    // =====================================================================

    static void printUsage(const char* progName) {
        std::cout << "Uso: " << progName << " [opcoes]\n\n";
        std::cout << "Opcoes:\n";
        std::cout << "  --firmware <arquivo>       Caminho para a imagem de firmware.bin\n";
        std::cout << "  --workspace <pasta>        Pasta raiz de saida (outputs)\n";
        std::cout << "  --threads <n>              Numero de threads para processamento concorrente\n";
        std::cout << "  --min-ascii <n>            Tamanho minimo de strings ASCII\n";
        std::cout << "  --min-utf16 <n>            Tamanho minimo de strings UTF16\n";
        std::cout << "  --qiling                   Habilita execucao opcional via Qiling\n";
        std::cout << "  --qiling-timeout <seg>     Timeout em segundos para Qiling\n";
        std::cout << "  --help                     Mostra esta ajuda e sai\n\n";

        std::cout << "Exemplo:\n";
        std::cout << "  " << progName << " --firmware inputs\\firmware.bin --workspace outputs --threads 4 --qiling --qiling-timeout 10\n";
    }


    bool BiosInspectorApp::parseArgs(int argc, char** argv, Config& cfg) {
        fs::path base = fs::current_path();

        // valores default baseados na tree
        cfg.workspaceDir = base / "outputs";
        cfg.firmwarePath = base / "inputs" / "firmware.bin";

        cfg.chipsecScript = base / "resources" / "chipsec-1.13.17" / "chipsec_util.py";
        cfg.uefiExtractExe = base / "resources" / "UEFIExtract_NE_A72_win64" / "UEFIExtract.exe";
        cfg.qilingScript   = base / "resources" / "qiling" / "qilingExec.py";

        cfg.sensitiveStringsFile = base / "inputs" / "BlackListStrings.txt";
        cfg.sensitiveGuidsFile   = base / "inputs" / "BlackListGUIDs.txt";

        // defaults ja definidos em Config para threads, minAscii, etc

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            auto next = [&](int& idx) -> std::string {
                if (idx + 1 < argc) return argv[++idx];
                return {};
            };

            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return false;
            } else if (arg == "--firmware") {
                cfg.firmwarePath = next(i);
            } else if (arg == "--workspace") {
                cfg.workspaceDir = next(i);
            } else if (arg == "--threads") {
                cfg.threads = std::stoi(next(i));
            } else if (arg == "--qiling") {
                cfg.enableQiling = true;
            } else if (arg == "--qiling-timeout") {
                cfg.qilingTimeoutSec = std::stoi(next(i));
            } else if (arg == "--min-ascii") {
                cfg.minAsciiLen = std::stoi(next(i));
            } else if (arg == "--min-utf16") {
                cfg.minUtf16Len = std::stoi(next(i));
            } else {
                std::cerr << "[!] Opcao desconhecida: " << arg << "\n";
                printUsage(argv[0]);
                return false;
            }
        }

        if (cfg.firmwarePath.empty() || !fs::exists(cfg.firmwarePath)) {
            std::cerr << "[!] Firmware nao encontrado em "
                    << cfg.firmwarePath << "\n";
            printUsage(argv[0]);
            return false;
        }

        prepareWorkspace(cfg);

        std::cout << "[cli] Firmware:   " << cfg.firmwarePath << "\n";
        std::cout << "[cli] Workspace:  " << cfg.workspaceDir << "\n";
        std::cout << "[cli] Threads:    " << cfg.threads << "\n";
        std::cout << "[cli] Qiling:     " << (cfg.enableQiling ? "ON" : "OFF") << "\n";
        std::cout << "[cli] Timeout:    " << cfg.qilingTimeoutSec << " s\n";
        std::cout << "[cli] min ASCII:  " << cfg.minAsciiLen << "\n";
        std::cout << "[cli] min UTF16:  " << cfg.minUtf16Len << "\n\n";

        return true;
    }


    void BiosInspectorApp::prepareWorkspace(Config& cfg) {
        fs::create_directories(cfg.workspaceDir);

        cfg.chipsecOutDir     = cfg.workspaceDir / "chipsec_outputs";
        cfg.uefiExtractOutDir = cfg.workspaceDir / "uefiextract_outputs";
        cfg.modulesDir        = cfg.workspaceDir / "modules";
        cfg.stringsOutDir     = cfg.workspaceDir / "strings";
        cfg.sensitiveOutDir   = cfg.workspaceDir / "sensitive";
        cfg.qilingLogsDir     = cfg.workspaceDir / "qiling_logs";
        cfg.manifestPath      = cfg.workspaceDir / "manifest.json";
        cfg.reportsDir        = cfg.workspaceDir / "reports";

        fs::create_directories(cfg.chipsecOutDir);
        fs::create_directories(cfg.uefiExtractOutDir);
        fs::create_directories(cfg.modulesDir);
        fs::create_directories(cfg.stringsOutDir);
        fs::create_directories(cfg.sensitiveOutDir);
        fs::create_directories(cfg.qilingLogsDir);
        fs::create_directories(cfg.reportsDir);
    }

    void BiosInspectorApp::buildModuleCatalog(const Config& cfg,
                                            const std::vector<fs::path>& modulePaths,
                                            Manifest& manifest) {
        manifest.firmwarePath = cfg.firmwarePath;
        manifest.modules.clear();

        if (modulePaths.empty()) {
            std::cout << "[catalog] Nenhum modulo .efi encontrado, manifest vazio\n";
            return;
        }

        // 1) Analise PE/COFF de todos modulos
        PeCoffAnalyzer peAnalyzer;
        std::vector<ModuleRecord> records;
        peAnalyzer.analyzeModules(cfg, modulePaths, records);

        // 2) Preparar componentes para strings, sensitive e Qiling
        StringExtractor stringExtractor;
        SensitiveMatcher sensitiveMatcher;
        sensitiveMatcher.loadPatterns(cfg);

        QilingExecutor qiling;

        ThreadPool pool(static_cast<size_t>(cfg.threads));

        // 3) Processar cada modulo em paralelo (strings, sensitive, qiling)
        for (auto& rec : records) {
            pool.enqueue([&cfg, &stringExtractor, &sensitiveMatcher, &qiling, &rec]() {
                // strings
                stringExtractor.extractStrings(cfg, rec);

                // sensitive
                sensitiveMatcher.run(cfg, rec);

                // qiling opcional
                if (cfg.enableQiling) {
                    rec.execStatus = qiling.executeModule(cfg, rec.path);
                }
            });
        }

        // Quando pool sair de escopo, destructor espera as threads
        // Então podemos mover os records para o manifest com segurança
        manifest.modules = std::move(records);
    }


    int BiosInspectorApp::run(int argc, char** argv) {
        Config cfg;
        if (!parseArgs(argc, argv, cfg))
            return 1;

        std::vector<fs::path> modules;

        ChipsecExtractor chipsec;
        UefiExtractExtractor uefi;
        
        std::cout << "\n=== FASE 1: CHIPSEC ===\n";
        chipsec.extract(cfg, modules);
        
        std::cout << "\n=== FASE 2: UEFIExtract (sempre, sobrescrevendo) ===\n";
        uefi.extract(cfg, modules);
        
        cleanupInputArtifacts(cfg);

        PeCoffAnalyzer peAnalyzer;
        std::vector<ModuleRecord> moduleRecords;
        std::cout << "\n=== FASE 3: PE/COFF Analyzer ===\n";
        peAnalyzer.analyzeModules(cfg, modules, moduleRecords);

        Manifest manifest;
        manifest.firmwarePath = cfg.firmwarePath;

        buildModuleCatalog(cfg, modules, manifest);

        ManifestDAO manifestDao;
        manifestDao.save(cfg, manifest);

        ReportDAO reportDao;
        reportDao.exportReports(cfg, manifest);


        std::cout << "[*] Analise concluida. Manifest em "
                  << cfg.manifestPath << "\n";
        return 0;
    }

} // namespace biosinspector

// =====================================================================
// main
// =====================================================================

int main(int argc, char** argv) {
    biosinspector::BiosInspectorApp app;
    return app.run(argc, argv);
}
