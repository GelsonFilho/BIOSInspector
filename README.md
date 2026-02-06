# BIOS Inspector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

**BIOS Inspector** is a command-line tool for **static** and optional **dynamic analysis** of **UEFI firmware modules**. It automates extraction, organization, inspection, and reporting of PE/COFF UEFI binaries (`.efi`) from a single firmware image, supporting large-scale security triage via structured artifacts like **JSON manifests**, **CSV summaries**, and **per-module reports**. (See the academic report for full context.)

> **Academic context:** The project was developed in the context of the Applied Computing Graduate Program (PPGCA) at the Federal University of Technology in Paraná (UTFPR), specifically for the **Advanced Programming** course, in the second semester of **2025**, under the supervision of **Professor Robson Ribeiro Linhares, PhD**.

---

## Contents
- [Key Features](#key-features)
- [Academic Work / PDF](#academic-work--pdf)
- [Software Explanation](#software-explanation)
- [Images & Examples](#images--examples)
- [UML Diagram](#uml-diagram)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Command-line Options](#command-line-options)
- [Output Structure](#output-structure)
- [Sensitive Patterns & GUID Lists](#sensitive-patterns--guid-lists)
- [Limitations & Roadmap](#limitations--roadmap)
- [How to Cite](#how-to-cite)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Key Features
- Automated extraction of UEFI modules using **CHIPSEC** and **UEFIExtract**.
- Static analysis: **PE/COFF metadata**, section listing, **Shannon entropy**, **SHA-256** (file and per section).
- ASCII/UTF-16 **string extraction** with configurable minimum length.
- **Sensitive-pattern matching** for strings and GUIDs based on user-provided lists.
- Consolidated **`manifest.json`**, plus **`modules_summary.csv`** and **`modules_report.txt`**.
- Optional **dynamic execution via Qiling**, with timeout and per-module logs.
- Parallel execution using a **thread pool** to speed up large firmware analyses.

---

## Academic Work / PDF
- 📄 **Full report (PDF)** available (in Brazilian Portuguese) at: [BIOS_Inspector.pdf](./BIOS_Inspector.pdf)

---

## Software Explanation
This section summarizes what a user sees and does with the tool, **without** implementation details. It mirrors the workflow from firmware image to consolidated outputs.

### 1) Input & Usage Scope
You start with a **single firmware image** (e.g., `firmware.bin`). BIOS Inspector creates a **workspace** and organizes all artifacts under `outputs/` (modules, strings, sensitive matches, reports, and logs). The goal is repeatable triage at scale with minimal manual steps.

### 2) Automatic Extraction of UEFI Modules
BIOS Inspector orchestrates **CHIPSEC** and **UEFIExtract** transparently. The tool extracts all `.efi` modules into `outputs/modules`, reporting progress in the terminal.

### 3) Per-Module Metrics & CSV View
For each `.efi` module, the tool records size, inferred architecture (from PE/COFF), section count, and **SHA-256** for the whole file and each section. It summarizes this into `outputs/reports/modules_summary.csv` for easy filtering, and into a textual `outputs/reports/modules_report.txt`.

### 4) Strings & Sensitive Patterns
It extracts **ASCII/UTF-16** strings into `outputs/strings/<module>.strings.txt` (including offsets and encoding). It also matches **sensitive strings and GUIDs** using your lists (`BlackListStrings.txt` and `BlackListGUIDs.txt`), saving matches as `outputs/sensitive/<module>.sensitive.txt`.

### 5) Consolidated Manifest & Firmware-level Reports
The tool writes a single **`manifest.json`** at the workspace root, consolidating PE/COFF info, sections, hashes, strings, sensitive matches, and optional execution status. This enables downstream processing without re-parsing binaries.

### 6) Optional Dynamic Execution with Qiling
If enabled, each module is emulated under **Qiling** with a **per-module timeout**. Logs go to `outputs/qiling_logs/`, and execution status is persisted in the manifest.

### 7) Command-line Operation & Profiles
All interaction is via **CLI** with parameters for firmware path, workspace, threads, minimum string length, and whether to enable Qiling. This supports both one-off lab sessions and CI/CD pipelines.

---

## Images & Examples
Below is a small gallery of artifacts and screens.

![Example artifact 1](docs/img/page3_Image32.jpg)

![Example artifact 2](docs/img/page3_Image34.jpg)

---

## UML Diagram
![UML diagram](docs/img/uml_diagram.png)

---

## Requirements
- **OS**: Windows (current primary support)
- **Compiler**: C++17 or newer
- The project is built using **MinGW-w64** (from **MSYS2**) through VS Code tasks.
- **VS Code** with the **C/C++ extension**
- **Python**: required for CHIPSEC and Qiling integration
- [CHIPSEC](https://github.com/chipsec/chipsec) (a version of this tool is already cloned in the `.
esources` folder of this project)
- [UEFIExtract](https://github.com/LongSoft/UEFITool) (the executable file for this tool is located in the `.
esources` folder of this project)
- [Qiling](https://github.com/qilingframework/qiling) (this Python library is required, use `pip install qiling` to install)

---

## Installation
This project does **NOT** use CMake.

### ✔ Building with VS Code (recommended)
Compilation is performed using **VS Code Build Tasks** together with **MinGW-w64** provided by **MSYS2**.

A preconfigured build task is already included in:
```
.vscode/tasks.json
```

### Requirements to compile:
- MSYS2 with MinGW-w64 installed
- VS Code C/C++ extension
- Your PATH pointing to MinGW-w64 (handled automatically by MSYS2 terminal)

### Installation (external documentation):
- [MSYS2 installation](https://www.msys2.org)
- [MinGW-w64 usage in MSYS2](https://www.msys2.org/docs/ci/#mingw)
- [VS Code tasks documentation](https://code.visualstudio.com/docs/editor/tasks)

### How to build in VS Code:
1. Open the project in VS Code
2. Open any `.cpp` file
3. Press **Ctrl + Shift + B**
4. Select the build task
5. The resulting `.exe` will appear next to the `.cpp` file

---

## Usage
```bash
BIOSInspector.exe --firmware "C:\path\to\firmware.bin" --workspace "C:\path\to\workspace"
```

With dynamic execution:
```bash
BIOSInspector.exe --firmware "firmware.bin" --workspace "workspace" --qiling on --qiling-timeout 30 --min-string-len 6 --threads 8
```

---

## Command-line Options
- `--firmware <file>`: firmware image to analyze
- `--workspace <folder>`: output directory (created if missing)
- `--threads <N>`: number of worker threads
- `--min-string-len <N>`: minimum length for extracted strings
- `--qiling on|off`: enable dynamic execution via Qiling
- `--qiling-timeout <sec>`: timeout per module when Qiling is enabled
- `--guid-blacklist <file>` / `--string-blacklist <file>`: lists for sensitive matches
- `--help`: display help

---

## Output Structure
```
workspace/
  outputs/
    modules/                 # extracted .efi modules
    strings/                 # <module>.strings.txt (ASCII/UTF-16 + offsets)
    sensitive/               # <module>.sensitive.txt (string/GUID matches)
    qiling_logs/             # logs per module (if Qiling enabled)
    reports/
      modules_summary.csv    # sortable triage table
      modules_report.txt     # human-readable summary
  manifest.json              # consolidated view for automation
```

---

## Sensitive Patterns & GUID Lists
- The person running this application can edit the lists as they see fit.
- **Strings**: `BlackListStrings.txt` (one term per line, substring match supported)
- **GUIDs**: `BlackListGUIDs.txt` (one GUID per line)

Matches are saved as `outputs/sensitive/*.sensitive.txt` with type, encoding, and approximate offset.

---

## Limitations & Roadmap
- Windows-focused at present
- Dynamic execution is optional and exploratory

**Future work**:
- Cross-platform support
- Additional static heuristics and rules
- Deeper Qiling integration
- Pipeline/DevSecOps integrations

---

## How to Cite
```
Almeida Filho, G. J. (2025). BIOS Inspector: Object-oriented tool for static and dynamic analysis of UEFI modules (Software). https://github.com/GelsonFilho/BIOSInspector
```

---

## License
This project is licensed under the **MIT License**. See [LICENSE](./LICENSE).

---

## Disclaimer
This repository was developed entirely as a personal project, outside working hours, without any use of code, confidential information, internal tools or resources from any employer. All content in this project is based solely on public information and open references. All opinions, mistakes and design decisions are the sole responsibility of the author and do not represent or bind any company, institution or organization.
