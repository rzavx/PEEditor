# PE Editor

A small, fast, dependency-free Win32 editor for **PE32 / PE32+** files (`.exe`, `.dll`, `.sys`, `.ocx`, `.scr`, `.cpl`, ...). Pure C++ / Win32 — no MFC, no ATL, no external libraries.

> Port of the classic MASM32 tool **"PE inFo"** by *Mouradpr*, rewritten in C++ for Visual Studio 2022, with PE32+ support, all 16 data directories, a full section-table editor (including adding new sections), an RVA → file-offset converter, `.bak` backups, and checksum fixing.

## Features

- **PE32 and PE32+** — automatically detected from the optional header's `Magic` field; fields that don't exist in the current format (e.g. `BaseOfData` in PE32+) are disabled rather than hidden.
- **Header editor** — every `IMAGE_FILE_HEADER` / `IMAGE_OPTIONAL_HEADER` field, shown and edited as hex.
- **Data Directories editor** — all 16 directory entries (Export, Import, Resource, Exception, Security, BaseReloc, Debug, TLS, LoadConfig, IAT, CLR Runtime, ...), with slots beyond `NumberOfRvaAndSizes` / `SizeOfOptionalHeader` automatically disabled.
- **Section table editor**
  - View and edit every section's Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, and Characteristics directly in the list.
  - **Add Section** — append a brand-new section to the file. The dialog suggests aligned name/size/offset defaults, lets you set `Characteristics` either by hex value or via checkboxes (Writable, Readable, Executable, Shareable, Code, Data Initialised, Data UnInitialised — kept in sync both ways), checks that there's free space in the header for a new section-table entry, **physically grows the file** to hold the new section's raw data, writes the new header entry, and updates `NumberOfSections` / `SizeOfImage` accordingly.
- **RVA → file offset converter**, aware of sections and of RVAs that fall in zero-padded (virtual-only) regions.
- **Decoded summary** — Magic, Machine, Subsystem, timestamp, Characteristics and DllCharacteristics flags, and where the entry point lands.
- **Safety**
  - Optional automatic `.bak` / `.bak2` / ... backup before the first write to a file.
  - Optional PE checksum fix on save.
  - Files that can't be opened for writing (read-only / in use) open in a safe, read-only view.
- Open via **File dialog**, **drag & drop**, or **command line** (`PEEditor.exe path\to\file.exe`).
- Crisp rendering on high-DPI screens; modern flat UI (Segoe UI, Consolas for hex fields).

## Building

Requirements: **Visual Studio 2022** with the "Desktop development with C++" workload (toolset v143, C++17).

1. Open `PEEditor.sln` in Visual Studio 2022.
2. Pick a configuration (`Debug`/`Release`) and platform (`x86`/`x64`).
3. Build (F7) — produces `PEEditor.exe`, a single self-contained executable with no extra runtime dependencies beyond standard Windows DLLs.

No NuGet packages, no third-party libraries — just the Win32 API and the standard C++ library.

## Usage

1. Launch `PEEditor.exe` and click **Open File** (or drag a file onto the window, or pass a path on the command line).
2. Use the **Header**, **Data Directories**, and **Sections** tabs to inspect or edit fields.
3. In the **Sections** tab:
   - Double-click any cell to edit that value.
   - Click **Add Section...** to append a new section (see above).
   - Enter an RVA to find out which section/file-offset it maps to.
4. Click **Save** to validate and write all pending Header/Data-Directory/Section-table edits to the file (section additions from the Add Section dialog are written immediately, since they also need to enlarge the file).

## Project structure

```
PEEditor/
├── main.cpp         # UI: dialogs, controls, event handling
├── pe_file.h/.cpp    # PE32/PE32+ file model (no UI code) — open/close, field
│                     #   access, data directories, section table, growing
│                     #   the file, checksum, backups
├── resource.h        # Control / dialog IDs
├── PEEditor.rc       # Dialog templates and resources
├── res/icon.ico      # Application icon
└── PEEditor.sln / PEEditor.vcxproj
```

## Disclaimer

This tool edits raw PE headers and section tables. Incorrect values can produce a file that no longer loads or runs correctly. Always keep the automatic backup enabled (or make your own copy) before editing files you care about.

## Credits

- Original MASM32 tool: **"PE inFo"** by Mouradpr.
- C++/Win32 port and extensions (PE32+, full data directories, section editing, RVA converter, Add Section, backups, checksum fix): this repository.
