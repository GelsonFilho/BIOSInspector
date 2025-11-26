#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <filesystem>
#include <mutex>
#include <functional>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <thread>

namespace fs = std::filesystem;

namespace biosinspector {

    // Configuração vinda da linha de comando
    struct Config {
        fs::path firmwarePath;
        fs::path workspaceDir;          // raiz de outputs
        fs::path chipsecScript;         // caminho para chipsec_util.py ou wrapper
        fs::path uefiExtractExe;        // caminho para UEFIExtract.exe
        fs::path qilingScript;          // qilingExec.py
        fs::path sensitiveStringsFile;  // BlackListStrings.txt
        fs::path sensitiveGuidsFile;    // BlackListGUIDs.txt

        int threads { 4 };
        int minAsciiLen { 4 };
        int minUtf16Len { 4 };
        int qilingTimeoutSec { 10 };
        bool enableQiling { false };

        // diretórios derivados
        fs::path modulesDir;
        fs::path chipsecOutDir;
        fs::path uefiExtractOutDir;
        fs::path stringsOutDir;
        fs::path sensitiveOutDir;
        fs::path qilingLogsDir;
        fs::path manifestPath;
        fs::path reportsDir;
    };

    // Informações de seção PE
    struct SectionInfo {
        std::string name;
        uint32_t rva { 0 };
        uint32_t vsize { 0 };
        uint32_t rawPtr { 0 };
        uint32_t rawSize { 0 };
        double entropy { 0.0 };
        std::string sha256_hex;
    };

    // Metadados PE por módulo
    struct PeInfo {
        bool is_pe { false };
        bool is64  { false };
        std::string error;

        uint16_t machine { 0 };
        uint16_t characteristics { 0 };
        uint16_t subsystem { 0 };

        uint64_t imageBase { 0 };
        uint32_t entryRva { 0 };
        uint32_t sizeOfImage { 0 };
        uint32_t sizeOfHeaders { 0 };
        uint32_t numSections { 0 };

        std::string file_sha256_hex;
        std::vector<SectionInfo> sections;
        std::vector<std::string> related_guids;
    };

    // Strings extraídas
    struct StringEntry {
        uint64_t offset { 0 };
        std::string value;
        bool isUtf16 { false };
    };

    // Match sensível
    struct SensitiveMatch {
        std::string pattern;
        uint64_t offset { 0 };
        bool isUtf16 { false };
        bool isGuid { false };
    };

    enum class ExecutionStatusKind {
        NotRun,
        Success,
        Error,
        Timeout
    };

    struct ExecutionStatus {
        ExecutionStatusKind status { ExecutionStatusKind::NotRun };
        int exitCode { 0 };
        std::string shortLog;  // log curto para manifest
        fs::path logFileOnDisk; // arquivo de log completo
    };

    // Registro completo de um módulo
    struct ModuleRecord {
        fs::path path;
        uint64_t fileSize { 0 };
        std::optional<std::time_t> lastWriteTime;

        PeInfo pe;
        std::vector<StringEntry> strings;
        std::vector<SensitiveMatch> sensitiveMatches;
        ExecutionStatus execStatus;
    };

    // Manifest completo
    struct Manifest {
        std::string toolName { "BIOS Inspector" };
        std::string toolVersion { "1.0" };
        fs::path firmwarePath;
        std::vector<ModuleRecord> modules;
    };

    // Interface para estratégia de extração de módulos
    class IModuleExtractor {
    public:
        virtual ~IModuleExtractor() = default;
        virtual bool extract(const Config& cfg, std::vector<fs::path>& outModules) = 0;
    };

    // Implementação usando CHIPSEC
    class ChipsecExtractor : public IModuleExtractor {
    public:
        bool extract(const Config& cfg, std::vector<fs::path>& outModules) override;
    };

    // Implementação usando UEFIExtract, usada como fallback
    class UefiExtractExtractor : public IModuleExtractor {
    public:
        bool extract(const Config& cfg, std::vector<fs::path>& outModules) override;
    };

    // Analisador PE COFF
    class PeCoffAnalyzer {
    public:
        void analyzeModules(const Config& cfg,
                            const std::vector<fs::path>& modules,
                            std::vector<ModuleRecord>& outRecords) const;
    };

    // Extrator de strings
    class StringExtractor {
    public:
        void extractStrings(const Config& cfg, ModuleRecord& mod);
    };

    // Matcher de termos sensíveis
    class SensitiveMatcher {
    public:
        void loadPatterns(const Config& cfg);
        void run(const Config& cfg, ModuleRecord& mod);
    private:
        std::vector<std::string> m_stringPatterns;
        std::vector<std::string> m_guidPatterns;
    };

    // Executor Qiling
    class QilingExecutor {
    public:
        ExecutionStatus executeModule(const Config& cfg, const fs::path& modulePath);
    };

    // Persistência do manifest em JSON
    class ManifestDAO {
    public:
        void save(const Config& cfg, const Manifest& manifest);
    };

    // Relatórios TXT e CSV
    class ReportDAO {
    public:
        void exportReports(const Config& cfg, const Manifest& manifest);
    };

    // Thread pool simples para processar módulos em paralelo
    class ThreadPool {
    public:
        explicit ThreadPool(size_t numThreads);
        ~ThreadPool();

        ThreadPool(const ThreadPool&) = delete;
        ThreadPool& operator=(const ThreadPool&) = delete;

        void enqueue(std::function<void()> task);

    private:
        std::vector<std::thread> m_workers;
        std::queue<std::function<void()>> m_tasks;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_stop { false };

        void workerLoop();
    };

    // Aplicação principal
    class BiosInspectorApp {
    public:
        int run(int argc, char** argv);

    private:
        bool parseArgs(int argc, char** argv, Config& cfg);
        void prepareWorkspace(Config& cfg);
        void buildModuleCatalog(const Config& cfg,
                                const std::vector<fs::path>& modulePaths,
                                Manifest& manifest);
    };

} // namespace biosinspector
