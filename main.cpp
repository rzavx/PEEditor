// PE Editor 1.0 - C++ port for Visual C++ 2022 (pure Win32, no MFC/ATL).
//
// Original: "PE inFo" (MASM32) by Mouradpr.
// Port additions: PE32 + PE32+, all 16 data directories, editable section
// table, RVA->offset converter, header decoding, .bak backup, checksum fix,
// command-line / drag&drop opening.
// UI: flat modern look (Segoe UI, banner header, accent buttons, Consolas hex fields).

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <windowsx.h>

#include <cstdint>
#include <string>
#include <vector>

#include "pe_file.h"
#include "resource.h"

#ifdef _MSC_VER
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "uxtheme.lib")
// Visual styles (replaces the old XP.xml manifest; works for x86 and x64).
#pragma comment(linker, "\"/manifestdependency:type='win32' "                  \
                        "name='Microsoft.Windows.Common-Controls' "            \
                        "version='6.0.0.0' processorArchitecture='*' "         \
                        "publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

namespace {

constexpr wchar_t kAppTitle[] = L"PE Editor";

enum Page { PG_HEADER, PG_DIRS, PG_SECTIONS, PG_COUNT };

HINSTANCE g_hInst = nullptr;
HWND      g_hMain = nullptr;
HWND      g_hTab = nullptr;
HWND      g_page[PG_COUNT] = {};

pe::File                          g_file;
std::vector<IMAGE_SECTION_HEADER> g_secs;       // working copy, written on Save
uint64_t                          g_secOffset = 0;  // where g_secs came from
bool                              g_backupDone = false;
bool                              g_loading = false;
std::wstring                      g_initialPath;

// Modern look ---------------------------------------------------------------
constexpr COLORREF kBannerBg  = RGB(28, 36, 54);
constexpr COLORREF kAccent    = RGB(15, 108, 189);
constexpr COLORREF kAccentHot = RGB(12, 92, 160);
constexpr COLORREF kAccentDn  = RGB(9, 72, 128);
constexpr COLORREF kPathBg    = RGB(246, 247, 249);

HBRUSH g_brWhite = nullptr, g_brBanner = nullptr, g_brAccent = nullptr, g_brPath = nullptr;
HFONT  g_fMono = nullptr, g_fTitle = nullptr, g_fSub = nullptr, g_fBold = nullptr;
HWND   g_hoverBtn = nullptr;
int    g_dpi = 96;

int Scale(int px) { return MulDiv(px, g_dpi, 96); }

HFONT MakeFont(const wchar_t* face, int pt, int weight) {
    return CreateFontW(-MulDiv(pt, g_dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

void InitLook(HWND hDlg) {
    HDC dc = GetDC(hDlg);
    g_dpi = GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(hDlg, dc);
    g_brWhite  = CreateSolidBrush(RGB(255, 255, 255));
    g_brBanner = CreateSolidBrush(kBannerBg);
    g_brAccent = CreateSolidBrush(kAccent);
    g_brPath   = CreateSolidBrush(kPathBg);
    g_fMono    = MakeFont(L"Consolas", 10, FW_NORMAL);
    g_fTitle   = MakeFont(L"Segoe UI Semibold", 17, FW_SEMIBOLD);
    g_fSub     = MakeFont(L"Segoe UI", 9, FW_NORMAL);
    g_fBold    = MakeFont(L"Segoe UI Semibold", 9, FW_SEMIBOLD);
}

void FreeLook() {
    for (HGDIOBJ o : {(HGDIOBJ)g_brWhite, (HGDIOBJ)g_brBanner, (HGDIOBJ)g_brAccent, (HGDIOBJ)g_brPath,
                      (HGDIOBJ)g_fMono, (HGDIOBJ)g_fTitle, (HGDIOBJ)g_fSub, (HGDIOBJ)g_fBold})
        if (o) DeleteObject(o);
}

BOOL CALLBACK SetMonoCb(HWND h, LPARAM) {
    wchar_t cls[16] = {};
    GetClassNameW(h, cls, 16);
    if (lstrcmpiW(cls, L"Edit") == 0) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g_fMono), TRUE);
    return TRUE;
}

// Hover tracking for the owner-drawn buttons.
LRESULT CALLBACK BtnSubclass(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) {
    switch (m) {
    case WM_MOUSEMOVE:
        if (g_hoverBtn != h) {
            g_hoverBtn = h;
            TRACKMOUSEEVENT t{sizeof(t), TME_LEAVE, h, 0};
            TrackMouseEvent(&t);
            InvalidateRect(h, nullptr, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        if (g_hoverBtn == h) g_hoverBtn = nullptr;
        InvalidateRect(h, nullptr, FALSE);
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(h, BtnSubclass, 1);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

void DrawFlatButton(const DRAWITEMSTRUCT* d) {
    const bool primary = true;  // every flat button uses the same blue style as Save
    const bool down = (d->itemState & ODS_SELECTED) != 0;
    const bool hot = d->hwndItem == g_hoverBtn;
    const bool off = (d->itemState & ODS_DISABLED) != 0;

    COLORREF fill, border, text;
    if (primary) {
        fill = down ? kAccentDn : hot ? kAccentHot : kAccent;
        border = fill;
        text = RGB(255, 255, 255);
    } else {
        fill = down ? RGB(210, 218, 232) : hot ? RGB(226, 233, 245) : RGB(240, 242, 246);
        border = hot ? kAccent : RGB(140, 148, 162);
        text = hot ? kAccentHot : RGB(30, 34, 44);
    }
    if (off) { fill = RGB(238, 238, 240); border = fill; text = RGB(150, 150, 150); }

    FillRect(d->hDC, &d->rcItem, g_brWhite);
    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ ob = SelectObject(d->hDC, br), op = SelectObject(d->hDC, pen);
    const int r = Scale(6);
    RoundRect(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom, r, r);
    SelectObject(d->hDC, ob);
    SelectObject(d->hDC, op);
    DeleteObject(br);
    DeleteObject(pen);

    wchar_t t[64] = {};
    GetWindowTextW(d->hwndItem, t, 64);
    HGDIOBJ of = SelectObject(d->hDC, g_fBold);
    SetBkMode(d->hDC, TRANSPARENT);
    SetTextColor(d->hDC, text);
    RECT tr = d->rcItem;
    if (down) OffsetRect(&tr, 0, 1);
    DrawTextW(d->hDC, t, -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(d->hDC, of);

    if ((d->itemState & ODS_FOCUS) && !(d->itemState & ODS_NOFOCUSRECT)) {
        RECT fr = d->rcItem;
        InflateRect(&fr, -Scale(4), -Scale(4));
        DrawFocusRect(d->hDC, &fr);
    }
}

void UpdateInfo();
void UpdateRvaResult();

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
HWND Ctl(int page, int id) { return GetDlgItem(g_page[page], id); }

std::wstring GetText(HWND h) {
    const int n = GetWindowTextLengthW(h);
    std::wstring s(static_cast<size_t>(n) + 1, L'\0');
    GetWindowTextW(h, &s[0], n + 1);
    s.resize(static_cast<size_t>(n));
    return s;
}

std::wstring Hex(uint64_t v, int digits) {
    std::wstring s(static_cast<size_t>(digits), L'0');
    for (int i = digits - 1; i >= 0; --i) {
        s[static_cast<size_t>(i)] = L"0123456789ABCDEF"[v & 0xF];
        v >>= 4;
    }
    return s;
}

// 1-16 hex digits, optional 0x prefix, surrounding blanks allowed.
bool ParseHex(const wchar_t* s, uint64_t& out) {
    while (*s == L' ' || *s == L'\t') ++s;
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    uint64_t v = 0;
    int digits = 0;
    for (;; ++s) {
        const wchar_t c = *s;
        uint32_t d;
        if (c >= L'0' && c <= L'9')      d = static_cast<uint32_t>(c - L'0');
        else if (c >= L'A' && c <= L'F') d = static_cast<uint32_t>(c - L'A' + 10);
        else if (c >= L'a' && c <= L'f') d = static_cast<uint32_t>(c - L'a' + 10);
        else break;
        if (digits >= 16) return false;
        v = (v << 4) | d;
        ++digits;
    }
    while (*s == L' ' || *s == L'\t') ++s;
    if (digits == 0 || *s != L'\0') return false;
    out = v;
    return true;
}

bool GetHexField(int page, int id, uint64_t& v) {
    return ParseHex(GetText(Ctl(page, id)).c_str(), v);
}

std::wstring SecName(const IMAGE_SECTION_HEADER& s) {
    std::wstring r;
    for (int i = 0; i < 8 && s.Name[i]; ++i) r += static_cast<wchar_t>(s.Name[i]);
    return r;
}

struct Flag { uint32_t bit; const wchar_t* name; };

const Flag kCharFlags[] = {
    {0x0001, L"NO_RELOCS"},       {0x0002, L"EXECUTABLE"},     {0x0004, L"NO_LINE_NUMS"},
    {0x0008, L"NO_LOCAL_SYMS"},   {0x0010, L"AGGRESSIVE_WS_TRIM"}, {0x0020, L"LARGE_ADDRESS_AWARE"},
    {0x0080, L"BYTES_REVERSED_LO"}, {0x0100, L"32BIT_MACHINE"}, {0x0200, L"NO_DEBUG"},
    {0x0400, L"REMOVABLE_RUN_FROM_SWAP"}, {0x0800, L"NET_RUN_FROM_SWAP"}, {0x1000, L"SYSTEM"},
    {0x2000, L"DLL"},             {0x4000, L"UP_SYSTEM_ONLY"}, {0x8000, L"BYTES_REVERSED_HI"},
};

const Flag kDllFlags[] = {
    {0x0020, L"HIGH_ENTROPY_VA"}, {0x0040, L"DYNAMIC_BASE (ASLR)"}, {0x0080, L"FORCE_INTEGRITY"},
    {0x0100, L"NX_COMPAT (DEP)"}, {0x0200, L"NO_ISOLATION"},        {0x0400, L"NO_SEH"},
    {0x0800, L"NO_BIND"},         {0x1000, L"APPCONTAINER"},        {0x2000, L"WDM_DRIVER"},
    {0x4000, L"GUARD_CF"},        {0x8000, L"TERMINAL_SERVER_AWARE"},
};

template <size_t N>
std::wstring FlagNames(uint32_t v, const Flag (&table)[N]) {
    std::wstring s;
    for (const Flag& f : table) {
        if (v & f.bit) {
            if (!s.empty()) s += L", ";
            s += f.name;
            v &= ~f.bit;
        }
    }
    if (v) {
        if (!s.empty()) s += L", ";
        s += L"0x" + Hex(v, 4);
    }
    return s.empty() ? std::wstring(L"-") : s;
}

const wchar_t* MachineName(uint64_t m) {
    switch (m) {
    case 0x014C: return L"Intel 386 (x86)";
    case 0x8664: return L"AMD64 (x64)";
    case 0x01C0: return L"ARM";
    case 0x01C4: return L"ARM Thumb-2";
    case 0xAA64: return L"ARM64";
    case 0x0200: return L"Itanium (IA-64)";
    case 0x0EBC: return L"EFI byte code";
    default:     return nullptr;
    }
}

const wchar_t* SubsystemName(uint64_t s) {
    switch (s) {
    case 1:  return L"Native";
    case 2:  return L"Windows GUI";
    case 3:  return L"Windows Console";
    case 5:  return L"OS/2 Console";
    case 7:  return L"POSIX Console";
    case 9:  return L"Windows CE GUI";
    case 10: return L"EFI Application";
    case 11: return L"EFI Boot Driver";
    case 12: return L"EFI Runtime Driver";
    case 13: return L"EFI ROM";
    case 14: return L"Xbox";
    case 16: return L"Windows Boot Application";
    default: return nullptr;
    }
}

std::wstring FormatTimestamp(uint64_t t) {
    ULARGE_INTEGER u;
    u.QuadPart = t * 10000000ULL + 116444736000000000ULL;
    FILETIME ft;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return L"?";
    wchar_t buf[40];
    wsprintfW(buf, L"%04d-%02d-%02d %02d:%02d:%02d UTC", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    return buf;
}

int MsgBox(HWND owner, const std::wstring& text, UINT flags, const wchar_t* title = kAppTitle) {
    return MessageBoxW(owner, text.c_str(), title, flags);
}

// ---------------------------------------------------------------------------
// Section list
// ---------------------------------------------------------------------------
const wchar_t* const kSecCols[] = {L"#", L"Name", L"VirtualSize", L"VirtualAddress",
                                   L"SizeOfRawData", L"PointerToRawData", L"Characteristics"};
constexpr int kSecColCount = 7;

std::wstring CellText(const IMAGE_SECTION_HEADER& s, int col) {
    switch (col) {
    case 1: return SecName(s);
    case 2: return Hex(s.Misc.VirtualSize, 8);
    case 3: return Hex(s.VirtualAddress, 8);
    case 4: return Hex(s.SizeOfRawData, 8);
    case 5: return Hex(s.PointerToRawData, 8);
    case 6: return Hex(s.Characteristics, 8);
    default: return L"";
    }
}

void SetRow(HWND lv, int row) {
    for (int c = 1; c < kSecColCount; ++c) {
        std::wstring t = CellText(g_secs[static_cast<size_t>(row)], c);
        ListView_SetItemText(lv, row, c, &t[0]);
    }
}

void FillSectionList() {
    HWND lv = Ctl(PG_SECTIONS, IDC_SEC_LIST);
    ListView_DeleteAllItems(lv);
    for (size_t i = 0; i < g_secs.size(); ++i) {
        std::wstring idx = std::to_wstring(i + 1);
        LVITEMW it{};
        it.mask = LVIF_TEXT;
        it.iItem = static_cast<int>(i);
        it.pszText = &idx[0];
        ListView_InsertItem(lv, &it);
        SetRow(lv, static_cast<int>(i));
    }
}

// ---------------------------------------------------------------------------
// UI <-> file
// ---------------------------------------------------------------------------
void ClearAll() {
    g_loading = true;
    for (int i = 0; i < pe::kFieldCount; ++i) {
        HWND e = Ctl(PG_HEADER, pe::kFields[i].id);
        EnableWindow(e, TRUE);
        SetWindowTextW(e, L"");
    }
    for (int i = 0; i < pe::kDirCount; ++i) {
        for (int id : {IDC_DIR_RVA_BASE + i, IDC_DIR_SIZE_BASE + i}) {
            HWND e = Ctl(PG_DIRS, id);
            EnableWindow(e, TRUE);
            SetWindowTextW(e, L"");
        }
    }
    g_secs.clear();
    g_secOffset = 0;
    ListView_DeleteAllItems(Ctl(PG_SECTIONS, IDC_SEC_LIST));
    SetDlgItemTextW(g_page[PG_SECTIONS], IDC_RVA_IN, L"");
    g_loading = false;
    UpdateInfo();
    UpdateRvaResult();
}

void ShowAll() {
    g_loading = true;

    for (int i = 0; i < pe::kFieldCount; ++i) {
        const pe::FieldDesc& f = pe::kFields[i];
        HWND e = Ctl(PG_HEADER, f.id);
        const int n = g_file.FieldBytes(f);
        if (n) {
            EnableWindow(e, TRUE);
            SetWindowTextW(e, Hex(g_file.Get(f), n * 2).c_str());
            SendMessageW(e, EM_SETLIMITTEXT, static_cast<WPARAM>(n * 2), 0);
        } else {
            EnableWindow(e, FALSE);
            SetWindowTextW(e, L"n/a");
        }
    }

    const int slots = g_file.DirSlots();
    for (int i = 0; i < pe::kDirCount; ++i) {
        const bool on = i < slots;
        HWND r = Ctl(PG_DIRS, IDC_DIR_RVA_BASE + i);
        HWND s = Ctl(PG_DIRS, IDC_DIR_SIZE_BASE + i);
        EnableWindow(r, on);
        EnableWindow(s, on);
        SetWindowTextW(r, on ? Hex(g_file.DirRva(i), 8).c_str() : L"");
        SetWindowTextW(s, on ? Hex(g_file.DirSize(i), 8).c_str() : L"");
    }

    bool truncated = false;
    g_file.LoadSections(g_secs, g_secOffset, truncated);
    FillSectionList();

    g_loading = false;
    UpdateInfo();
    UpdateRvaResult();
}

void UpdateInfo() {
    if (!g_page[PG_HEADER]) return;
    uint64_t v = 0;

    std::vector<std::wstring> parts;
    if (GetHexField(PG_HEADER, IDC_ED_MAGIC, v)) {
        parts.push_back(std::wstring(L"Magic: ") +
                        (v == 0x10B ? L"PE32" : v == 0x20B ? L"PE32+" : L"unknown"));
    }
    if (GetHexField(PG_HEADER, IDC_ED_MACHINE, v)) {
        const wchar_t* n = MachineName(v);
        parts.push_back(std::wstring(L"Machine: ") + (n ? n : L"unknown"));
    }
    if (GetHexField(PG_HEADER, IDC_ED_SUBSYSTEM, v)) {
        const wchar_t* n = SubsystemName(v);
        parts.push_back(std::wstring(L"Subsystem: ") + (n ? n : L"unknown"));
    }
    if (GetHexField(PG_HEADER, IDC_ED_TIMEDATESTAMP, v))
        parts.push_back(L"Time: " + FormatTimestamp(v));
    std::wstring line1;
    for (size_t i = 0; i < parts.size(); ++i) line1 += (i ? L"   |   " : L"") + parts[i];

    std::wstring line2, line3, line4;
    if (GetHexField(PG_HEADER, IDC_ED_CHARACTERISTICS, v))
        line2 = L"Characteristics: " + FlagNames(static_cast<uint32_t>(v), kCharFlags);
    if (GetHexField(PG_HEADER, IDC_ED_DLLCHARACTERISTICS, v))
        line3 = L"DllCharacteristics: " + FlagNames(static_cast<uint32_t>(v), kDllFlags);

    uint64_t ep = 0, soh = 0;
    if (!g_secs.empty() && GetHexField(PG_HEADER, IDC_ED_ENTRYPOINT, ep)) {
        GetHexField(PG_HEADER, IDC_ED_SIZEOFHEADERS, soh);
        const pe::RvaInfo r = pe::RvaToOffset(g_secs, static_cast<uint32_t>(soh),
                                              static_cast<uint32_t>(ep));
        if (!r.found) {
            line4 = L"EntryPoint: RVA is not inside any section";
        } else {
            line4 = L"EntryPoint: section " +
                    (r.section >= 0 ? SecName(g_secs[static_cast<size_t>(r.section)])
                                    : std::wstring(L"(headers)")) +
                    L", file offset " + Hex(r.offset, 8);
            if (!r.inFile) line4 += L" (not stored in file)";
        }
    }

    SetDlgItemTextW(g_page[PG_HEADER], IDC_INFO1, line1.c_str());
    SetDlgItemTextW(g_page[PG_HEADER], IDC_INFO2, line2.c_str());
    SetDlgItemTextW(g_page[PG_HEADER], IDC_INFO3, line3.c_str());
    SetDlgItemTextW(g_page[PG_HEADER], IDC_INFO4, line4.c_str());
}

void UpdateRvaResult() {
    HWND page = g_page[PG_SECTIONS];
    if (!page) return;
    const std::wstring t = GetText(GetDlgItem(page, IDC_RVA_IN));
    std::wstring out;
    uint64_t rva = 0;
    if (!t.empty()) {
        if (!ParseHex(t.c_str(), rva) || rva > 0xFFFFFFFFULL) {
            out = L"Invalid hex value";
        } else {
            uint64_t soh = 0;
            GetHexField(PG_HEADER, IDC_ED_SIZEOFHEADERS, soh);
            const pe::RvaInfo r = pe::RvaToOffset(g_secs, static_cast<uint32_t>(soh),
                                                  static_cast<uint32_t>(rva));
            if (!r.found) {
                out = L"RVA is not inside any section or the headers";
            } else {
                out = L"File offset: " + Hex(r.offset, 8) + L"   (" +
                      (r.section >= 0 ? SecName(g_secs[static_cast<size_t>(r.section)])
                                      : std::wstring(L"headers")) + L")";
                if (!r.inFile) out += L" - not stored in file";
            }
        }
    }
    SetDlgItemTextW(page, IDC_RVA_OUT, out.c_str());
}

void SelectTab(int i) {
    TabCtrl_SetCurSel(g_hTab, i);
    for (int p = 0; p < PG_COUNT; ++p) ShowWindow(g_page[p], p == i ? SW_SHOW : SW_HIDE);
}

void LoadFile(HWND hDlg, const wchar_t* path) {
    const pe::OpenStatus st = g_file.Open(path);
    g_backupDone = false;
    if (st != pe::OpenStatus::Ok) {
        ClearAll();
        SetDlgItemTextW(hDlg, IDC_FILE_PATH, L"");
        SetWindowTextW(hDlg, kAppTitle);
        const wchar_t* msg = L"Sorry This File is not a valid PE Or Link of Program...";
        if (st == pe::OpenStatus::CannotOpen) msg = L"Could not open the file.";
        else if (st == pe::OpenStatus::BadMagic)
            msg = L"Unsupported optional header (Magic is neither PE32 nor PE32+).";
        MsgBox(hDlg, msg, MB_OK | MB_ICONWARNING);
        return;
    }
    SetDlgItemTextW(hDlg, IDC_FILE_PATH, path);
    std::wstring title = std::wstring(kAppTitle) + L" - " + path;
    if (g_file.IsReadOnly()) title += L"  [read-only]";
    SetWindowTextW(hDlg, title.c_str());
    ShowAll();
}

// ---------------------------------------------------------------------------
// Input dialog used to edit one section value
// ---------------------------------------------------------------------------
struct InputCtx {
    std::wstring title, prompt, text;
    bool hex = true;
    int  maxLen = 8;
};

INT_PTR CALLBACK InputProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_INITDIALOG: {
        InputCtx* c = reinterpret_cast<InputCtx*>(l);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(c));
        SetWindowTextW(h, c->title.c_str());
        SetDlgItemTextW(h, IDC_IN_PROMPT, c->prompt.c_str());
        SetDlgItemTextW(h, IDC_IN_EDIT, c->text.c_str());
        SendDlgItemMessageW(h, IDC_IN_EDIT, EM_SETLIMITTEXT, static_cast<WPARAM>(c->maxLen), 0);
        SendDlgItemMessageW(h, IDC_IN_EDIT, EM_SETSEL, 0, -1);
        SetFocus(GetDlgItem(h, IDC_IN_EDIT));
        return FALSE;  // focus set manually
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            InputCtx* c = reinterpret_cast<InputCtx*>(GetWindowLongPtrW(h, GWLP_USERDATA));
            const std::wstring t = GetText(GetDlgItem(h, IDC_IN_EDIT));
            if (c->hex) {
                uint64_t v = 0;
                if (!ParseHex(t.c_str(), v) || v > 0xFFFFFFFFULL) {
                    MsgBox(h, L"Enter 1 to 8 hex digits.", MB_OK | MB_ICONEXCLAMATION);
                    return TRUE;
                }
            } else {
                bool ok = !t.empty() && t.size() <= 8;
                for (wchar_t ch : t) ok = ok && ch >= 0x20 && ch <= 0x7E;
                if (!ok) {
                    MsgBox(h, L"Section names are 1 to 8 ASCII characters.", MB_OK | MB_ICONEXCLAMATION);
                    return TRUE;
                }
            }
            c->text = t;
            EndDialog(h, IDOK);
            return TRUE;
        }
        if (LOWORD(w) == IDCANCEL) {
            EndDialog(h, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void EditSectionCell(int row, int col) {
    if (row < 0 || static_cast<size_t>(row) >= g_secs.size() || col < 1 || col >= kSecColCount)
        return;
    IMAGE_SECTION_HEADER& s = g_secs[static_cast<size_t>(row)];

    InputCtx ctx;
    ctx.hex = col != 1;
    ctx.title = L"Edit section " + SecName(s);
    ctx.prompt = std::wstring(kSecCols[col]) + (ctx.hex ? L" (hex):" : L" (text):");
    ctx.text = CellText(s, col);
    if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_INPUT), g_hMain, InputProc,
                        reinterpret_cast<LPARAM>(&ctx)) != IDOK)
        return;

    if (col == 1) {
        for (int i = 0; i < 8; ++i)
            s.Name[i] = i < static_cast<int>(ctx.text.size()) ? static_cast<BYTE>(ctx.text[static_cast<size_t>(i)]) : 0;
    } else {
        uint64_t v = 0;
        ParseHex(ctx.text.c_str(), v);
        const DWORD d = static_cast<DWORD>(v);
        switch (col) {
        case 2: s.Misc.VirtualSize = d; break;
        case 3: s.VirtualAddress = d; break;
        case 4: s.SizeOfRawData = d; break;
        case 5: s.PointerToRawData = d; break;
        case 6: s.Characteristics = d; break;
        }
    }
    SetRow(Ctl(PG_SECTIONS, IDC_SEC_LIST), row);
    UpdateInfo();
    UpdateRvaResult();
}

// ---------------------------------------------------------------------------
// Add Section dialog
// ---------------------------------------------------------------------------
uint64_t AlignUp(uint64_t v, uint64_t a) {
    if (a == 0) return v;
    return (v + a - 1) / a * a;
}

const pe::FieldDesc* FindField(int id) {
    for (int i = 0; i < pe::kFieldCount; ++i)
        if (pe::kFields[i].id == id) return &pe::kFields[i];
    return nullptr;
}

constexpr uint32_t kDefaultSectionChars =
    IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

uint32_t CharFromChecks(HWND h) {
    uint32_t c = 0;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_WRITABLE)   == BST_CHECKED) c |= IMAGE_SCN_MEM_WRITE;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_READABLE)   == BST_CHECKED) c |= IMAGE_SCN_MEM_READ;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_EXECUTABLE) == BST_CHECKED) c |= IMAGE_SCN_MEM_EXECUTE;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_SHAREABLE)  == BST_CHECKED) c |= IMAGE_SCN_MEM_SHARED;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_CODE)       == BST_CHECKED) c |= IMAGE_SCN_CNT_CODE;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_DATAINIT)   == BST_CHECKED) c |= IMAGE_SCN_CNT_INITIALIZED_DATA;
    if (IsDlgButtonChecked(h, IDC_AS_CHK_DATAUNINIT) == BST_CHECKED) c |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    return c;
}

void SyncChecksFromChar(HWND h, uint32_t c) {
    CheckDlgButton(h, IDC_AS_CHK_WRITABLE,   (c & IMAGE_SCN_MEM_WRITE)   ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_AS_CHK_READABLE,   (c & IMAGE_SCN_MEM_READ)    ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_AS_CHK_EXECUTABLE, (c & IMAGE_SCN_MEM_EXECUTE) ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_AS_CHK_SHAREABLE,  (c & IMAGE_SCN_MEM_SHARED)  ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_AS_CHK_CODE,       (c & IMAGE_SCN_CNT_CODE)    ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_AS_CHK_DATAINIT,   (c & IMAGE_SCN_CNT_INITIALIZED_DATA)   ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_AS_CHK_DATAUNINIT, (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) ? BST_CHECKED : BST_UNCHECKED);
}

INT_PTR CALLBACK AddSectionProc(HWND h, UINT m, WPARAM w, LPARAM) {
    switch (m) {
    case WM_INITDIALOG: {
        SendDlgItemMessageW(h, IDC_AS_NAME, EM_SETLIMITTEXT, 8, 0);
        for (int id : {IDC_AS_VSIZE, IDC_AS_VOFFSET, IDC_AS_RSIZE, IDC_AS_ROFFSET, IDC_AS_CHAR})
            SendDlgItemMessageW(h, id, EM_SETLIMITTEXT, 8, 0);

        uint64_t soh = 0, salign = 0, falign = 0;
        GetHexField(PG_HEADER, IDC_ED_SIZEOFHEADERS, soh);
        GetHexField(PG_HEADER, IDC_ED_SECTIONALIGNMENT, salign);
        GetHexField(PG_HEADER, IDC_ED_FILEALIGNMENT, falign);
        if (!salign) salign = 0x1000;
        if (!falign) falign = 0x200;

        uint64_t nextV = AlignUp(soh, salign);
        uint64_t nextR = AlignUp(soh, falign);
        if (!g_secs.empty()) {
            const IMAGE_SECTION_HEADER& last = g_secs.back();
            const uint64_t lastVSize = last.Misc.VirtualSize ? last.Misc.VirtualSize : last.SizeOfRawData;
            nextV = AlignUp(static_cast<uint64_t>(last.VirtualAddress) + lastVSize, salign);
            nextR = AlignUp(static_cast<uint64_t>(last.PointerToRawData) + last.SizeOfRawData, falign);
        }

        SetDlgItemTextW(h, IDC_AS_NAME, L"newsec");
        SetDlgItemTextW(h, IDC_AS_VSIZE, Hex(0x1000, 8).c_str());
        SetDlgItemTextW(h, IDC_AS_VOFFSET, Hex(nextV, 8).c_str());
        SetDlgItemTextW(h, IDC_AS_RSIZE, Hex(AlignUp(0x1000, falign), 8).c_str());
        SetDlgItemTextW(h, IDC_AS_ROFFSET, Hex(nextR, 8).c_str());
        SetDlgItemTextW(h, IDC_AS_CHAR, Hex(kDefaultSectionChars, 8).c_str());
        SyncChecksFromChar(h, kDefaultSectionChars);
        SendDlgItemMessageW(h, IDC_AS_NAME, EM_SETSEL, 0, -1);
        SetFocus(GetDlgItem(h, IDC_AS_NAME));
        return FALSE;  // focus set manually
    }
    case WM_COMMAND: {
        const int id = LOWORD(w);
        if (HIWORD(w) == BN_CLICKED &&
            (id == IDC_AS_CHK_WRITABLE || id == IDC_AS_CHK_READABLE || id == IDC_AS_CHK_EXECUTABLE ||
             id == IDC_AS_CHK_SHAREABLE || id == IDC_AS_CHK_CODE || id == IDC_AS_CHK_DATAINIT ||
             id == IDC_AS_CHK_DATAUNINIT)) {
            SetDlgItemTextW(h, IDC_AS_CHAR, Hex(CharFromChecks(h), 8).c_str());
            return TRUE;
        }
        if (id == IDC_AS_CHAR && HIWORD(w) == EN_CHANGE) {
            uint64_t v = 0;
            if (ParseHex(GetText(GetDlgItem(h, IDC_AS_CHAR)).c_str(), v))
                SyncChecksFromChar(h, static_cast<uint32_t>(v));
            return TRUE;
        }
        if (id == IDCANCEL && HIWORD(w) == BN_CLICKED) {
            EndDialog(h, IDCANCEL);
            return TRUE;
        }
        if (id != IDC_AS_BTN_ADD || HIWORD(w) != BN_CLICKED) break;

        // --- Validate -----------------------------------------------------
        const std::wstring name = GetText(GetDlgItem(h, IDC_AS_NAME));
        bool nameOk = !name.empty() && name.size() <= 8;
        for (wchar_t ch : name) nameOk = nameOk && ch >= 0x20 && ch <= 0x7E;
        if (!nameOk) {
            MsgBox(h, L"Section name must be 1 to 8 ASCII characters.", MB_OK | MB_ICONEXCLAMATION);
            return TRUE;
        }

        uint64_t vsize = 0, voff = 0, rsize = 0, roff = 0, chars = 0;
        struct NumField { int id; const wchar_t* label; uint64_t* out; };
        const NumField nums[] = {
            {IDC_AS_VSIZE,   L"Virtual Size",   &vsize},
            {IDC_AS_VOFFSET, L"Virtual Offset", &voff},
            {IDC_AS_RSIZE,   L"Raw Size",       &rsize},
            {IDC_AS_ROFFSET, L"Raw Offset",     &roff},
            {IDC_AS_CHAR,    L"Characteristic", &chars},
        };
        for (const NumField& n : nums) {
            if (!ParseHex(GetText(GetDlgItem(h, n.id)).c_str(), *n.out) || *n.out > 0xFFFFFFFFULL) {
                MsgBox(h, std::wstring(n.label) + L": enter 1 to 8 hex digits.", MB_OK | MB_ICONEXCLAMATION);
                return TRUE;
            }
        }
        if (vsize == 0 || rsize == 0) {
            MsgBox(h, L"Virtual Size and Raw Size must not be zero.", MB_OK | MB_ICONEXCLAMATION);
            return TRUE;
        }

        uint64_t salign = 0, falign = 0;
        GetHexField(PG_HEADER, IDC_ED_SECTIONALIGNMENT, salign);
        GetHexField(PG_HEADER, IDC_ED_FILEALIGNMENT, falign);
        if (!salign) salign = 0x1000;
        if (!falign) falign = 0x200;

        const uint64_t alignedVOff  = AlignUp(voff, salign);
        const uint64_t alignedROff  = AlignUp(roff, falign);
        const uint64_t alignedRSize = AlignUp(rsize, falign);

        // Room for one more section-table entry before the first section's
        // raw data (or SizeOfHeaders, if there are no sections yet).
        uint64_t firstRaw = 0;
        GetHexField(PG_HEADER, IDC_ED_SIZEOFHEADERS, firstRaw);
        for (const IMAGE_SECTION_HEADER& s : g_secs)
            if (s.PointerToRawData && (firstRaw == 0 || s.PointerToRawData < firstRaw))
                firstRaw = s.PointerToRawData;
        const uint64_t newEntryEnd =
            g_secOffset + (g_secs.size() + 1) * sizeof(IMAGE_SECTION_HEADER);
        if (newEntryEnd > firstRaw) {
            MsgBox(h, L"There is no free space left in the header area for another "
                      L"section-table entry.", MB_OK | MB_ICONEXCLAMATION);
            return TRUE;
        }

        // --- Backup (once per opened file, before the first modification) -
        if (!g_backupDone && IsDlgButtonChecked(g_hMain, IDC_CHK_BACKUP) == BST_CHECKED) {
            std::wstring bak;
            if (g_file.CreateBackup(&bak)) {
                g_backupDone = true;
            } else if (MsgBox(h, L"The backup copy could not be created. Continue anyway?",
                              MB_YESNO | MB_ICONWARNING) == IDYES) {
                g_backupDone = true;
            } else {
                return TRUE;
            }
        }

        // --- Enlarge the file and write everything -------------------------
        const uint64_t newFileSize = alignedROff + alignedRSize;
        if (!g_file.Grow(newFileSize)) {
            MsgBox(h, L"Could not enlarge the file.", MB_OK | MB_ICONEXCLAMATION);
            return TRUE;
        }

        IMAGE_SECTION_HEADER sec{};
        for (int i = 0; i < 8; ++i)
            sec.Name[i] = i < static_cast<int>(name.size())
                              ? static_cast<BYTE>(name[static_cast<size_t>(i)]) : 0;
        sec.Misc.VirtualSize = static_cast<DWORD>(vsize);
        sec.VirtualAddress   = static_cast<DWORD>(alignedVOff);
        sec.SizeOfRawData    = static_cast<DWORD>(alignedRSize);
        sec.PointerToRawData = static_cast<DWORD>(alignedROff);
        sec.Characteristics  = static_cast<DWORD>(chars);

        g_secs.push_back(sec);
        if (!g_file.StoreSections(g_secs, g_secOffset)) {
            g_secs.pop_back();
            MsgBox(h, L"The section table could not be written.", MB_OK | MB_ICONEXCLAMATION);
            return TRUE;
        }

        if (const pe::FieldDesc* f = FindField(IDC_ED_NUMBEROFSECTIONS))
            g_file.Set(*f, g_secs.size());
        if (const pe::FieldDesc* f = FindField(IDC_ED_SIZEOFIMAGE)) {
            const uint64_t need = AlignUp(alignedVOff + vsize, salign);
            if (g_file.Get(*f) < need) g_file.Set(*f, need);
        }

        g_file.Flush();
        EndDialog(h, IDOK);
        return TRUE;
    }
    }
    return FALSE;
}

void OnAddSection(HWND owner) {
    if (!g_file.IsOpen()) {
        MsgBox(owner, L"Open a PE file first.", MB_OK | MB_ICONEXCLAMATION);
        return;
    }
    if (g_file.IsReadOnly()) {
        MsgBox(owner, L"The file was opened read-only (protected or in use), so it cannot be modified.",
               MB_OK | MB_ICONEXCLAMATION, L"Error");
        return;
    }
    if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_ADD_SECTION), g_hMain, AddSectionProc, 0) == IDOK) {
        g_file.RefreshFormat();
        ShowAll();
        MsgBox(g_hMain, L"Section added and written to the file.", MB_OK | MB_ICONINFORMATION, L"Success");
    }
}

// ---------------------------------------------------------------------------
// Page dialog procedures
// ---------------------------------------------------------------------------
INT_PTR CALLBACK HeaderPageProc(HWND, UINT m, WPARAM w, LPARAM) {
    if (m == WM_COMMAND && HIWORD(w) == EN_CHANGE && !g_loading) UpdateInfo();
    return FALSE;
}

INT_PTR CALLBACK DirsPageProc(HWND h, UINT m, WPARAM, LPARAM) {
    if (m == WM_INITDIALOG) {
        for (int i = 0; i < pe::kDirCount; ++i) {
            SendDlgItemMessageW(h, IDC_DIR_RVA_BASE + i, EM_SETLIMITTEXT, 8, 0);
            SendDlgItemMessageW(h, IDC_DIR_SIZE_BASE + i, EM_SETLIMITTEXT, 8, 0);
        }
    }
    return FALSE;
}

INT_PTR CALLBACK SectionsPageProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_INITDIALOG: {
        HWND lv = GetDlgItem(h, IDC_SEC_LIST);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        ListView_SetImageList(lv, ImageList_Create(1, Scale(26), ILC_COLOR32, 1, 1), LVSIL_SMALL);  // row height
        SendMessageW(lv, WM_SETFONT, reinterpret_cast<WPARAM>(g_fMono), TRUE);
        SetWindowTheme(lv, L"Explorer", nullptr);
        static const int widths[kSecColCount] = {40, 90, 110, 120, 120, 140, 130};
        for (int i = 0; i < kSecColCount; ++i) {
            LVCOLUMNW c{};
            c.mask = LVCF_TEXT | LVCF_WIDTH;
            c.pszText = const_cast<LPWSTR>(kSecCols[i]);
            c.cx = Scale(widths[i]);
            ListView_InsertColumn(lv, i, &c);
        }
        SendDlgItemMessageW(h, IDC_RVA_IN, EM_SETLIMITTEXT, 8, 0);
        return FALSE;
    }
    case WM_NOTIFY: {
        const NMHDR* nm = reinterpret_cast<const NMHDR*>(l);
        if (nm->idFrom == IDC_SEC_LIST && nm->code == NM_DBLCLK) {
            const NMITEMACTIVATE* a = reinterpret_cast<const NMITEMACTIVATE*>(l);
            LVHITTESTINFO ht{};
            ht.pt = a->ptAction;
            ListView_SubItemHitTest(nm->hwndFrom, &ht);
            if (ht.iItem >= 0 && ht.iSubItem >= 1) EditSectionCell(ht.iItem, ht.iSubItem);
            SetWindowLongPtrW(h, DWLP_MSGRESULT, 0);
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDC_RVA_IN && HIWORD(w) == EN_CHANGE) {
            UpdateRvaResult();
        } else if (LOWORD(w) == IDC_BTN_USE_EP && HIWORD(w) == BN_CLICKED) {
            SetDlgItemTextW(h, IDC_RVA_IN, GetText(Ctl(PG_HEADER, IDC_ED_ENTRYPOINT)).c_str());
        } else if (LOWORD(w) == IDC_BTN_ADD_SECTION && HIWORD(w) == BN_CLICKED) {
            OnAddSection(h);
        }
        break;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Main dialog actions
// ---------------------------------------------------------------------------
void OnOpen(HWND hDlg) {
    std::vector<wchar_t> buffer(32768, L'\0');
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hDlg;
    ofn.lpstrFilter = L"PE files\0*.exe;*.dll;*.sys;*.ocx;*.scr;*.cpl\0All files\0*.*\0";
    ofn.lpstrFile = buffer.data();
    ofn.nMaxFile = static_cast<DWORD>(buffer.size());
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) LoadFile(hDlg, buffer.data());
}

void OnDropFiles(HWND hDlg, HDROP drop) {
    const UINT len = DragQueryFileW(drop, 0, nullptr, 0);
    std::vector<wchar_t> path(static_cast<size_t>(len) + 1, L'\0');
    DragQueryFileW(drop, 0, path.data(), len + 1);
    DragFinish(drop);
    LoadFile(hDlg, path.data());
}

void FocusError(int page, int id, const std::wstring& msg) {
    SelectTab(page);
    MsgBox(g_hMain, msg, MB_OK | MB_ICONEXCLAMATION, L"Error");
    HWND e = Ctl(page, id);
    SetFocus(e);
    SendMessageW(e, EM_SETSEL, 0, -1);
}

void OnSave(HWND hDlg) {
    if (!g_file.IsOpen()) {
        MsgBox(hDlg, L"Could not Save... Please Select File", MB_OK | MB_ICONEXCLAMATION, L"Error");
        return;
    }
    if (g_file.IsReadOnly()) {
        MsgBox(hDlg, L"The file was opened read-only (protected or in use), so it cannot be modified.",
               MB_OK | MB_ICONEXCLAMATION, L"Error");
        return;
    }

    // 1. Validate everything first - a typo must never leave a half-written file.
    struct Pending { const pe::FieldDesc* f; uint64_t v; };
    std::vector<Pending> fields;
    for (int i = 0; i < pe::kFieldCount; ++i) {
        const pe::FieldDesc& f = pe::kFields[i];
        const int n = g_file.FieldBytes(f);
        if (!n) continue;
        uint64_t v = 0;
        std::wstring err;
        if (!GetHexField(PG_HEADER, f.id, v))
            err = std::wstring(f.name) + L": enter 1 to " + std::to_wstring(n * 2) + L" hex digits.";
        else if (n < 8 && (v >> (8 * n)) != 0)
            err = std::wstring(f.name) + L": value is too large for a " + std::to_wstring(n) + L"-byte field.";
        if (!err.empty()) {
            FocusError(PG_HEADER, f.id, err);
            return;
        }
        fields.push_back({&f, v});
    }

    const int slots = g_file.DirSlots();
    std::vector<std::pair<uint32_t, uint32_t>> dirs(static_cast<size_t>(slots));
    for (int i = 0; i < slots; ++i) {
        uint64_t rva = 0, size = 0;
        const int idRva = IDC_DIR_RVA_BASE + i, idSize = IDC_DIR_SIZE_BASE + i;
        if (!GetHexField(PG_DIRS, idRva, rva) || rva > 0xFFFFFFFFULL) {
            FocusError(PG_DIRS, idRva, L"Directory " + std::to_wstring(i) + L" RVA: enter 1 to 8 hex digits.");
            return;
        }
        if (!GetHexField(PG_DIRS, idSize, size) || size > 0xFFFFFFFFULL) {
            FocusError(PG_DIRS, idSize, L"Directory " + std::to_wstring(i) + L" Size: enter 1 to 8 hex digits.");
            return;
        }
        dirs[static_cast<size_t>(i)] = {static_cast<uint32_t>(rva), static_cast<uint32_t>(size)};
    }

    // 2. Backup (once per opened file, before the first modification).
    std::wstring note;
    if (!g_backupDone && IsDlgButtonChecked(hDlg, IDC_CHK_BACKUP) == BST_CHECKED) {
        std::wstring bak;
        if (g_file.CreateBackup(&bak)) {
            note += L"\r\nBackup: " + bak;
        } else if (MsgBox(hDlg, L"The backup copy could not be created. Save anyway?",
                          MB_YESNO | MB_ICONWARNING) != IDYES) {
            return;
        }
        g_backupDone = true;
    }

    // 3. Write. Sections go to the place they were loaded from; header
    //    fields are written last so an explicit edit always wins.
    if (!g_secs.empty() && !g_file.StoreSections(g_secs, g_secOffset))
        note += L"\r\nWarning: the section table lies outside the file and was not written.";
    for (const Pending& p : fields) g_file.Set(*p.f, p.v);
    for (int i = 0; i < slots; ++i)
        g_file.SetDir(i, dirs[static_cast<size_t>(i)].first, dirs[static_cast<size_t>(i)].second);

    if (IsDlgButtonChecked(hDlg, IDC_CHK_CHECKSUM) == BST_CHECKED)
        note += L"\r\nCheckSum updated: " + Hex(g_file.UpdateChecksum(), 8);

    const bool flushed = g_file.Flush();
    g_file.RefreshFormat();
    ShowAll();  // show what is really in the file now

    if (!flushed)
        MsgBox(hDlg, L"Changes were made but could not be flushed to disk.", MB_OK | MB_ICONEXCLAMATION, L"Error");
    else
        MsgBox(hDlg, L"File has been Modified" + note, MB_OK | MB_ICONINFORMATION, L"Success");
}

void LayoutPages(HWND hDlg) {
    RECT rc;
    GetClientRect(g_hTab, &rc);
    TabCtrl_AdjustRect(g_hTab, FALSE, &rc);
    MapWindowPoints(g_hTab, hDlg, reinterpret_cast<POINT*>(&rc), 2);
    for (HWND p : g_page)
        SetWindowPos(p, HWND_TOP, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                     SWP_NOACTIVATE);
}

INT_PTR CALLBACK MainProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        g_hMain = hDlg;
        InitLook(hDlg);
        SendDlgItemMessageW(hDlg, IDC_TITLE, WM_SETFONT, reinterpret_cast<WPARAM>(g_fTitle), FALSE);
        SendDlgItemMessageW(hDlg, IDC_SUBTITLE, WM_SETFONT, reinterpret_cast<WPARAM>(g_fSub), FALSE);
        SendDlgItemMessageW(hDlg, IDC_FILE_PATH, WM_SETFONT, reinterpret_cast<WPARAM>(g_fMono), FALSE);
        for (int id : {IDC_BTN_OPEN, IDC_BTN_SAVE, IDC_BTN_EXIT})
            SetWindowSubclass(GetDlgItem(hDlg, id), BtnSubclass, 1, 0);
        const int cxs = GetSystemMetrics(SM_CXSMICON), cys = GetSystemMetrics(SM_CYSMICON);
        const int cxb = GetSystemMetrics(SM_CXICON), cyb = GetSystemMetrics(SM_CYICON);
        SendMessageW(hDlg, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(
            LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, cxs, cys, LR_SHARED)));
        SendMessageW(hDlg, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(
            LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, cxb, cyb, LR_SHARED)));

        g_hTab = GetDlgItem(hDlg, IDC_TAB);
        static const wchar_t* const tabs[PG_COUNT] = {L"Header", L"Data Directories", L"Sections"};
        for (int i = 0; i < PG_COUNT; ++i) {
            TCITEMW t{};
            t.mask = TCIF_TEXT;
            t.pszText = const_cast<LPWSTR>(tabs[i]);
            SendMessageW(g_hTab, TCM_INSERTITEMW, static_cast<WPARAM>(i), reinterpret_cast<LPARAM>(&t));
        }
        g_page[PG_HEADER] = CreateDialogParamW(g_hInst, MAKEINTRESOURCEW(IDD_PAGE_HEADER), hDlg, HeaderPageProc, 0);
        g_page[PG_DIRS] = CreateDialogParamW(g_hInst, MAKEINTRESOURCEW(IDD_PAGE_DIRS), hDlg, DirsPageProc, 0);
        g_page[PG_SECTIONS] = CreateDialogParamW(g_hInst, MAKEINTRESOURCEW(IDD_PAGE_SECTIONS), hDlg, SectionsPageProc, 0);
        for (HWND p : g_page) {
            EnableThemeDialogTexture(p, ETDT_ENABLETAB);
            EnumChildWindows(p, SetMonoCb, 0);
        }
        LayoutPages(hDlg);
        SelectTab(PG_HEADER);

        CheckDlgButton(hDlg, IDC_CHK_BACKUP, BST_CHECKED);
        if (!g_initialPath.empty()) LoadFile(hDlg, g_initialPath.c_str());
        return TRUE;
    }
    case WM_NOTIFY: {
        const NMHDR* nm = reinterpret_cast<const NMHDR*>(lParam);
        if (nm->hwndFrom == g_hTab && nm->code == TCN_SELCHANGE) {
            SelectTab(TabCtrl_GetCurSel(g_hTab));
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_OPEN:  OnOpen(hDlg);  return TRUE;
        case IDC_BTN_SAVE:  OnSave(hDlg);  return TRUE;
        case IDC_BTN_EXIT:  EndDialog(hDlg, 0); return TRUE;
        case IDOK:
        case IDCANCEL:      return TRUE;  // Enter / Esc must not close the editor
        }
        break;
    case WM_DRAWITEM:
        DrawFlatButton(reinterpret_cast<const DRAWITEMSTRUCT*>(lParam));
        return TRUE;
    case WM_CTLCOLORDLG:
        return reinterpret_cast<INT_PTR>(g_brWhite);
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        const int id = GetDlgCtrlID(reinterpret_cast<HWND>(lParam));
        if (id == IDC_BANNER || id == IDC_TITLE || id == IDC_SUBTITLE || id == IDC_ACCENT) {
            SetBkColor(dc, id == IDC_ACCENT ? kAccent : kBannerBg);
            SetTextColor(dc, id == IDC_SUBTITLE ? RGB(176, 196, 224) : RGB(255, 255, 255));
            return reinterpret_cast<INT_PTR>(id == IDC_ACCENT ? g_brAccent : g_brBanner);
        }
        if (id == IDC_FILE_PATH) {
            SetBkColor(dc, kPathBg);
            SetTextColor(dc, RGB(40, 40, 40));
            return reinterpret_cast<INT_PTR>(g_brPath);
        }
        break;
    }
    case WM_DROPFILES:
        OnDropFiles(hDlg, reinterpret_cast<HDROP>(wParam));
        return TRUE;
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }
    return FALSE;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    g_hInst = hInstance;

    // Crisp rendering on high-DPI screens (resolved dynamically: needs Windows 10 1607+).
    if (HMODULE u32 = GetModuleHandleW(L"user32.dll")) {
        using SetCtxFn = BOOL(WINAPI*)(HANDLE);
        if (auto fn = reinterpret_cast<SetCtxFn>(GetProcAddress(u32, "SetProcessDpiAwarenessContext")))
            fn(reinterpret_cast<HANDLE>(-2));  // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE
    }

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    int argc = 0;
    if (LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc)) {
        if (argc >= 2) g_initialPath = argv[1];
        LocalFree(argv);
    }

    DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, MainProc, 0);

    g_file.Close();
    FreeLook();
    return 0;
}
