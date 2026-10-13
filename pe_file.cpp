#include "pe_file.h"

#include <algorithm>
#include <cstddef>
#include <cstring>

#include "resource.h"

namespace pe {

#define OFF_(T, m) static_cast<uint16_t>(offsetof(T, m))
#define SZ_(T, m)  static_cast<uint8_t>(sizeof(static_cast<T*>(nullptr)->m))
#define FIELD_(id, label, m)                                                   \
    { id, L##label, OFF_(IMAGE_NT_HEADERS32, m), OFF_(IMAGE_NT_HEADERS64, m),  \
      SZ_(IMAGE_NT_HEADERS32, m), SZ_(IMAGE_NT_HEADERS64, m) }

const FieldDesc kFields[] = {
    FIELD_(IDC_ED_ENTRYPOINT,              "EntryPoint",                  OptionalHeader.AddressOfEntryPoint),
    FIELD_(IDC_ED_IMAGEBASE,               "ImageBase",                   OptionalHeader.ImageBase),
    FIELD_(IDC_ED_SIZEOFIMAGE,             "SizeOfImage",                 OptionalHeader.SizeOfImage),
    FIELD_(IDC_ED_BASEOFCODE,              "BaseOfCode",                  OptionalHeader.BaseOfCode),
    // BaseOfData exists only in PE32.
    { IDC_ED_BASEOFDATA, L"BaseOfData", OFF_(IMAGE_NT_HEADERS32, OptionalHeader.BaseOfData), 0,
      SZ_(IMAGE_NT_HEADERS32, OptionalHeader.BaseOfData), 0 },
    FIELD_(IDC_ED_SECTIONALIGNMENT,        "SectionAlignment",            OptionalHeader.SectionAlignment),
    FIELD_(IDC_ED_FILEALIGNMENT,           "FileAlignment",               OptionalHeader.FileAlignment),
    FIELD_(IDC_ED_MAGIC,                   "Magic",                       OptionalHeader.Magic),
    FIELD_(IDC_ED_MAJORLINKERVERSION,      "MajorLinkerVersion",          OptionalHeader.MajorLinkerVersion),
    FIELD_(IDC_ED_MINORLINKERVERSION,      "MinorLinkerVersion",          OptionalHeader.MinorLinkerVersion),
    FIELD_(IDC_ED_SIZEOFCODE,              "SizeOfCode",                  OptionalHeader.SizeOfCode),
    FIELD_(IDC_ED_SIZEOFINITIALIZEDDATA,   "SizeOfInitializedData",       OptionalHeader.SizeOfInitializedData),
    FIELD_(IDC_ED_SIZEOFUNINITIALIZEDDATA, "SizeOfUninitializedData",     OptionalHeader.SizeOfUninitializedData),
    FIELD_(IDC_ED_MAJOROSVERSION,          "MajorOperatingSystemVersion", OptionalHeader.MajorOperatingSystemVersion),
    FIELD_(IDC_ED_MINOROSVERSION,          "MinorOperatingSystemVersion", OptionalHeader.MinorOperatingSystemVersion),
    FIELD_(IDC_ED_MAJORIMAGEVERSION,       "MajorImageVersion",           OptionalHeader.MajorImageVersion),
    FIELD_(IDC_ED_MINORIMAGEVERSION,       "MinorImageVersion",           OptionalHeader.MinorImageVersion),
    FIELD_(IDC_ED_MAJORSUBSYSVERSION,      "MajorSubsystemVersion",       OptionalHeader.MajorSubsystemVersion),
    FIELD_(IDC_ED_MINORSUBSYSVERSION,      "MinorSubsystemVersion",       OptionalHeader.MinorSubsystemVersion),
    FIELD_(IDC_ED_SUBSYSTEM,               "Subsystem",                   OptionalHeader.Subsystem),
    FIELD_(IDC_ED_DLLCHARACTERISTICS,      "DllCharacteristics",          OptionalHeader.DllCharacteristics),
    FIELD_(IDC_ED_WIN32VERSIONVALUE,       "Win32VersionValue",           OptionalHeader.Win32VersionValue),
    FIELD_(IDC_ED_SIZEOFHEADERS,           "SizeOfHeaders",               OptionalHeader.SizeOfHeaders),
    FIELD_(IDC_ED_CHECKSUM,                "CheckSum",                    OptionalHeader.CheckSum),
    FIELD_(IDC_ED_STACKRESERVE,            "SizeOfStackReserve",          OptionalHeader.SizeOfStackReserve),
    FIELD_(IDC_ED_STACKCOMMIT,             "SizeOfStackCommit",           OptionalHeader.SizeOfStackCommit),
    FIELD_(IDC_ED_HEAPRESERVE,             "SizeOfHeapReserve",           OptionalHeader.SizeOfHeapReserve),
    FIELD_(IDC_ED_HEAPCOMMIT,              "SizeOfHeapCommit",            OptionalHeader.SizeOfHeapCommit),
    FIELD_(IDC_ED_LOADERFLAGS,             "LoaderFlags",                 OptionalHeader.LoaderFlags),
    FIELD_(IDC_ED_NUMBEROFRVAANDSIZES,     "NumberOfRvaAndSizes",         OptionalHeader.NumberOfRvaAndSizes),
    FIELD_(IDC_ED_MACHINE,                 "Machine",                     FileHeader.Machine),
    FIELD_(IDC_ED_NUMBEROFSECTIONS,        "NumberOfSections",            FileHeader.NumberOfSections),
    FIELD_(IDC_ED_TIMEDATESTAMP,           "TimeDateStamp",               FileHeader.TimeDateStamp),
    FIELD_(IDC_ED_CHARACTERISTICS,         "Characteristics",             FileHeader.Characteristics),
    FIELD_(IDC_ED_SIZEOFOPTIONALHEADER,    "SizeOfOptionalHeader",        FileHeader.SizeOfOptionalHeader),
    FIELD_(IDC_ED_POINTERTOSYMBOLTABLE,    "PointerToSymbolTable",        FileHeader.PointerToSymbolTable),
    FIELD_(IDC_ED_NUMBEROFSYMBOLS,         "NumberOfSymbols",             FileHeader.NumberOfSymbols),
};
const int kFieldCount = static_cast<int>(sizeof(kFields) / sizeof(kFields[0]));

namespace {

constexpr size_t kOptOff      = offsetof(IMAGE_NT_HEADERS32, OptionalHeader);
constexpr size_t kMagicOff    = offsetof(IMAGE_NT_HEADERS32, OptionalHeader.Magic);
constexpr size_t kChecksumOff = offsetof(IMAGE_NT_HEADERS32, OptionalHeader.CheckSum);
constexpr size_t kSizeOptOff  = offsetof(IMAGE_NT_HEADERS32, FileHeader.SizeOfOptionalHeader);
constexpr size_t kNumSecOff   = offsetof(IMAGE_NT_HEADERS32, FileHeader.NumberOfSections);

// Layout facts the code relies on (PE specification).
static_assert(kOptOff == offsetof(IMAGE_NT_HEADERS64, OptionalHeader), "layout");
static_assert(kChecksumOff == offsetof(IMAGE_NT_HEADERS64, OptionalHeader.CheckSum), "layout");
static_assert(kChecksumOff == 0x58, "layout");
static_assert(offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase) == 0x34, "layout");
static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase) == 0x30, "layout");
static_assert(offsetof(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory) == 0x78, "layout");
static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory) == 0x88, "layout");

template <class T>
T ReadAs(const BYTE* p) {
    T v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

Format FormatFromMagic(uint16_t m) {
    if (m == IMAGE_NT_OPTIONAL_HDR32_MAGIC) return Format::Pe32;
    if (m == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return Format::Pe64;
    return Format::None;
}

size_t NtSize(Format f) {
    return f == Format::Pe64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
}

size_t DirTableOffset(Format f) {
    return f == Format::Pe64 ? offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory)
                             : offsetof(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory);
}

size_t NumRvaOffset(Format f) {
    return f == Format::Pe64 ? offsetof(IMAGE_NT_HEADERS64, OptionalHeader.NumberOfRvaAndSizes)
                             : offsetof(IMAGE_NT_HEADERS32, OptionalHeader.NumberOfRvaAndSizes);
}

}  // namespace

RvaInfo RvaToOffset(const std::vector<IMAGE_SECTION_HEADER>& secs,
                    uint32_t sizeOfHeaders, uint32_t rva) {
    RvaInfo r;
    for (size_t i = 0; i < secs.size(); ++i) {
        const IMAGE_SECTION_HEADER& s = secs[i];
        const uint64_t span = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (rva >= s.VirtualAddress && static_cast<uint64_t>(rva) - s.VirtualAddress < span) {
            const uint32_t delta = rva - s.VirtualAddress;
            r.found = true;
            r.section = static_cast<int>(i);
            r.offset = s.PointerToRawData + delta;
            r.inFile = delta < s.SizeOfRawData;
            return r;
        }
    }
    if (rva < sizeOfHeaders) {
        r.found = true;
        r.inFile = true;
        r.section = -1;
        r.offset = rva;
    }
    return r;
}

// ---------------------------------------------------------------------------

OpenStatus File::Open(const wchar_t* path) {
    Close();
    path_ = path;

    file_ = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    readOnly_ = false;
    if (file_ == INVALID_HANDLE_VALUE) {
        // Read-only or in use: still allow viewing.
        file_ = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        readOnly_ = true;
    }
    if (file_ == INVALID_HANDLE_VALUE) {
        file_ = nullptr;
        return Fail(OpenStatus::CannotOpen);
    }

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(file_, &sz)) return Fail(OpenStatus::CannotOpen);
    size_ = static_cast<uint64_t>(sz.QuadPart);
    if (size_ < sizeof(IMAGE_DOS_HEADER)) return Fail(OpenStatus::NotPE);

    map_ = CreateFileMappingW(file_, nullptr, readOnly_ ? PAGE_READONLY : PAGE_READWRITE,
                              0, 0, nullptr);
    if (!map_) return Fail(OpenStatus::CannotOpen);

    view_ = static_cast<BYTE*>(MapViewOfFile(
        map_, readOnly_ ? FILE_MAP_READ : (FILE_MAP_READ | FILE_MAP_WRITE), 0, 0, 0));
    if (!view_) return Fail(OpenStatus::CannotOpen);

    if (ReadAs<uint16_t>(view_) != IMAGE_DOS_SIGNATURE) return Fail(OpenStatus::NotPE);

    const uint64_t off = ReadAs<uint32_t>(view_ + offsetof(IMAGE_DOS_HEADER, e_lfanew));
    if (off + kMagicOff + 2 > size_) return Fail(OpenStatus::NotPE);

    BYTE* nt = view_ + off;
    if (ReadAs<uint32_t>(nt) != IMAGE_NT_SIGNATURE) return Fail(OpenStatus::NotPE);

    const Format f = FormatFromMagic(ReadAs<uint16_t>(nt + kMagicOff));
    if (f == Format::None) return Fail(OpenStatus::BadMagic);
    if (off + NtSize(f) > size_) return Fail(OpenStatus::NotPE);

    nt_ = nt;
    ntOff_ = static_cast<uint64_t>(off);
    fmt_ = f;
    return OpenStatus::Ok;
}

void File::Close() {
    nt_ = nullptr;
    ntOff_ = 0;
    fmt_ = Format::None;
    size_ = 0;
    if (view_) { UnmapViewOfFile(view_); view_ = nullptr; }
    if (map_)  { CloseHandle(map_);      map_ = nullptr; }
    if (file_) { CloseHandle(file_);     file_ = nullptr; }
    readOnly_ = false;
}

size_t File::FieldOffset(const FieldDesc& f) const {
    return fmt_ == Format::Pe64 ? f.off64 : f.off32;
}

int File::FieldBytes(const FieldDesc& f) const {
    if (!nt_) return 0;
    return fmt_ == Format::Pe64 ? f.size64 : f.size32;
}

uint64_t File::Get(const FieldDesc& f) const {
    const int n = FieldBytes(f);
    uint64_t v = 0;  // little-endian host: zero-extends smaller fields
    if (n) std::memcpy(&v, nt_ + FieldOffset(f), static_cast<size_t>(n));
    return v;
}

void File::Set(const FieldDesc& f, uint64_t value) {
    const int n = FieldBytes(f);
    if (n) std::memcpy(nt_ + FieldOffset(f), &value, static_cast<size_t>(n));
}

int File::DirSlots() const {
    if (!nt_) return 0;
    const size_t dirOffInOpt = DirTableOffset(fmt_) - kOptOff;
    const uint32_t declared = ReadAs<uint32_t>(nt_ + NumRvaOffset(fmt_));
    const uint16_t optSize = ReadAs<uint16_t>(nt_ + kSizeOptOff);
    if (optSize <= dirOffInOpt) return 0;
    const uint32_t fit = static_cast<uint32_t>((optSize - dirOffInOpt) / sizeof(IMAGE_DATA_DIRECTORY));
    return static_cast<int>(std::min<uint32_t>({declared, fit, static_cast<uint32_t>(kDirCount)}));
}

uint32_t File::DirRva(int i) const {
    return ReadAs<uint32_t>(nt_ + DirTableOffset(fmt_) + sizeof(IMAGE_DATA_DIRECTORY) * i);
}

uint32_t File::DirSize(int i) const {
    return ReadAs<uint32_t>(nt_ + DirTableOffset(fmt_) + sizeof(IMAGE_DATA_DIRECTORY) * i + 4);
}

void File::SetDir(int i, uint32_t rva, uint32_t size) {
    BYTE* p = nt_ + DirTableOffset(fmt_) + sizeof(IMAGE_DATA_DIRECTORY) * i;
    std::memcpy(p, &rva, 4);
    std::memcpy(p + 4, &size, 4);
}

size_t File::LoadSections(std::vector<IMAGE_SECTION_HEADER>& out,
                          uint64_t& tableOffset, bool& truncated) const {
    out.clear();
    truncated = false;
    tableOffset = 0;
    if (!nt_) return 0;
    const uint16_t count = ReadAs<uint16_t>(nt_ + kNumSecOff);
    const uint16_t opt = ReadAs<uint16_t>(nt_ + kSizeOptOff);
    const uint64_t base = static_cast<uint64_t>(nt_ - view_) + kOptOff + opt;
    tableOffset = base;
    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t p = base + static_cast<uint64_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (p + sizeof(IMAGE_SECTION_HEADER) > size_) { truncated = true; break; }
        out.push_back(ReadAs<IMAGE_SECTION_HEADER>(view_ + p));
    }
    return out.size();
}

bool File::StoreSections(const std::vector<IMAGE_SECTION_HEADER>& secs, uint64_t tableOffset) {
    if (!view_ || readOnly_) return false;
    const uint64_t end = tableOffset + secs.size() * sizeof(IMAGE_SECTION_HEADER);
    if (end > size_) return false;  // check everything first, then write
    for (size_t i = 0; i < secs.size(); ++i)
        std::memcpy(view_ + tableOffset + i * sizeof(IMAGE_SECTION_HEADER), &secs[i],
                    sizeof(IMAGE_SECTION_HEADER));
    return true;
}

bool File::Grow(uint64_t newSize) {
    if (!view_ || readOnly_) return false;
    if (newSize <= size_) return true;  // nothing to do

    // The mapping must be torn down before the underlying file can be resized.
    UnmapViewOfFile(view_);
    view_ = nullptr;
    CloseHandle(map_);
    map_ = nullptr;

    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(newSize);
    const bool resized = SetFilePointerEx(file_, li, nullptr, FILE_BEGIN) && SetEndOfFile(file_);

    // Remap regardless of the outcome above, so the object stays usable
    // (at its old size if the resize failed).
    const uint64_t mapSize = resized ? newSize : size_;
    map_ = CreateFileMappingW(file_, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (map_) view_ = static_cast<BYTE*>(MapViewOfFile(map_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
    if (!view_) { nt_ = nullptr; return false; }  // object is no longer usable
    nt_ = view_ + ntOff_;

    if (!resized) return false;

    // Windows normally zero-fills newly allocated file regions already, but
    // do it explicitly so the new section's raw data starts out clean.
    std::memset(view_ + size_, 0, static_cast<size_t>(mapSize - size_));
    size_ = mapSize;
    return true;
}

void File::RefreshFormat() {
    if (!nt_) return;
    const Format f = FormatFromMagic(ReadAs<uint16_t>(nt_ + kMagicOff));
    if (f == Format::None || f == fmt_) return;
    if (static_cast<uint64_t>(nt_ - view_) + NtSize(f) <= size_) fmt_ = f;
}

uint32_t File::UpdateChecksum() {
    const uint32_t zero = 0;
    std::memcpy(nt_ + kChecksumOff, &zero, 4);  // field counts as zero

    uint32_t sum = 0;
    uint64_t i = 0;
    for (; i + 1 < size_; i += 2) {
        sum += ReadAs<uint16_t>(view_ + i);
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (size_ & 1) {
        sum += view_[size_ - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);

    const uint32_t result = sum + static_cast<uint32_t>(size_);
    std::memcpy(nt_ + kChecksumOff, &result, 4);
    return result;
}

bool File::CreateBackup(std::wstring* backupPath) const {
    if (!view_) return false;
    for (int i = 0; i < 100; ++i) {
        std::wstring name = path_ + L".bak";
        if (i) name += std::to_wstring(i + 1);
        HANDLE h = CreateFileW(name.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            const DWORD e = GetLastError();
            if (e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS) continue;
            return false;
        }
        bool ok = true;
        uint64_t done = 0;
        while (done < size_) {
            const DWORD chunk = static_cast<DWORD>(std::min<uint64_t>(size_ - done, 1u << 24));
            DWORD written = 0;
            if (!WriteFile(h, view_ + done, chunk, &written, nullptr) || written != chunk) {
                ok = false;
                break;
            }
            done += chunk;
        }
        CloseHandle(h);
        if (!ok) { DeleteFileW(name.c_str()); return false; }
        if (backupPath) *backupPath = name;
        return true;
    }
    return false;
}

bool File::Flush() {
    return view_ && FlushViewOfFile(view_, 0) != 0;
}

}  // namespace pe
