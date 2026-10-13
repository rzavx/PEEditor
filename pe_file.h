// PE (PE32 / PE32+) file model used by the editor. Contains no UI code.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace pe {

enum class Format { None, Pe32, Pe64 };
enum class OpenStatus { Ok, CannotOpen, NotPE, BadMagic };

constexpr int kDirCount = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;  // 16

// One editable header field. Offsets are relative to the "PE\0\0" signature.
struct FieldDesc {
    int            id;      // dialog control id
    const wchar_t* name;
    uint16_t       off32;
    uint16_t       off64;
    uint8_t        size32;  // 0 = field does not exist in this format
    uint8_t        size64;
};

extern const FieldDesc kFields[];
extern const int       kFieldCount;

struct RvaInfo {
    bool     found   = false;
    bool     inFile  = false;  // false: RVA lies in zero-padded (virtual-only) part
    int      section = -1;     // -1 = inside the headers
    uint32_t offset  = 0;
};
RvaInfo RvaToOffset(const std::vector<IMAGE_SECTION_HEADER>& secs,
                    uint32_t sizeOfHeaders, uint32_t rva);

class File {
public:
    File() = default;
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    ~File() { Close(); }

    OpenStatus Open(const wchar_t* path);
    void       Close();

    bool                IsOpen() const { return nt_ != nullptr; }
    bool                IsReadOnly() const { return readOnly_; }
    Format              GetFormat() const { return fmt_; }
    const std::wstring& Path() const { return path_; }

    // Header fields (0 bytes = field absent in the current format).
    int      FieldBytes(const FieldDesc& f) const;
    uint64_t Get(const FieldDesc& f) const;
    void     Set(const FieldDesc& f, uint64_t value);

    // Data directories. DirSlots() = number of entries that really belong to
    // the optional header (NumberOfRvaAndSizes / SizeOfOptionalHeader aware).
    int      DirSlots() const;
    uint32_t DirRva(int i) const;
    uint32_t DirSize(int i) const;
    void     SetDir(int i, uint32_t rva, uint32_t size);

    // Section table. LoadSections stops at the end of the file.
    size_t LoadSections(std::vector<IMAGE_SECTION_HEADER>& out,
                        uint64_t& tableOffset, bool& truncated) const;
    bool   StoreSections(const std::vector<IMAGE_SECTION_HEADER>& secs,
                         uint64_t tableOffset);

    // Physically enlarges the file to newSize (no-op if newSize <= current
    // size). The appended region is zero-filled. Needed before a new
    // section's raw data can be written. Remaps the file, so any raw
    // pointer previously obtained from this object becomes invalid; use
    // Get()/Set()/LoadSections()/StoreSections() afterwards as usual.
    bool Grow(uint64_t newSize);
    uint64_t Size() const { return size_; }

    // Re-detects PE32/PE32+ from the Magic field (call after writing).
    void RefreshFormat();

    // Computes the standard PE checksum of the whole file, stores it in the
    // header and returns it.
    uint32_t UpdateChecksum();

    // Copies the (still unmodified) file to <path>.bak, .bak2, ...
    bool CreateBackup(std::wstring* backupPath) const;

    bool Flush();

private:
    OpenStatus Fail(OpenStatus s) { Close(); return s; }
    size_t     FieldOffset(const FieldDesc& f) const;

    HANDLE       file_ = nullptr;
    HANDLE       map_ = nullptr;
    BYTE*        view_ = nullptr;
    BYTE*        nt_ = nullptr;  // IMAGE_NT_HEADERS inside view_
    uint64_t     ntOff_ = 0;     // nt_ - view_; kept so Grow() can rebase nt_
    uint64_t     size_ = 0;
    Format       fmt_ = Format::None;
    bool         readOnly_ = false;
    std::wstring path_;
};

}  // namespace pe
