#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <type_traits>
#endif

/** I want to use functions in pycdas.cpp directly, but not moving them to
 * another file, to sync with upstream in the future easily.
 */
#define main pycdas_main
# include "pycdas.cpp"
#undef main

#include "ASTree.h"

const char* VERSION = "v0.2.2";

#ifdef _WIN32

// Windows: Use SEH/UEF; prefer calling only Win32 APIs
#ifdef __cpp_lib_fstream_native_handle
static HANDLE g_dc_h  = INVALID_HANDLE_VALUE;
static HANDLE g_das_h = INVALID_HANDLE_VALUE;
#endif

static LONG WINAPI av_handler(EXCEPTION_POINTERS* /*ep*/) {
    const char msg[] = "Access violation caught. Best-effort FlushFileBuffers.\n";
    DWORD wrote = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), msg, sizeof(msg) - 1, &wrote, nullptr);
#ifdef __cpp_lib_fstream_native_handle
    if (g_das_h != INVALID_HANDLE_VALUE) FlushFileBuffers(g_das_h);
    if (g_dc_h  != INVALID_HANDLE_VALUE) FlushFileBuffers(g_dc_h);
#endif
    TerminateProcess(GetCurrentProcess(), 0xC0000005);
    return EXCEPTION_EXECUTE_HANDLER;
}

struct SehInstall {
    SehInstall() {
        // Suppress WER popups; let the UEF handle it directly
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        SetUnhandledExceptionFilter(av_handler);
    }
} seh_install_guard;

#else  // !_WIN32

#ifdef __cpp_lib_fstream_native_handle
static int g_dc_fd = -1;
static int g_das_fd = -1;

static void segv_handler(int sig) {
    const char msg[] = "Access violation caught. Best-effort fsync.\n";
    // Only use async-signal-safe functions
    write(STDERR_FILENO, msg, sizeof(msg)-1);
    if (g_das_fd != -1) fsync(g_das_fd);
    if (g_dc_fd  != -1) fsync(g_dc_fd);
    _Exit(128 + sig);
}
#else
static void segv_handler(int sig) {
    const char msg[] = "Access violation caught.\n";
    write(STDERR_FILENO, msg, sizeof(msg)-1);
    _Exit(128 + sig);
}
#endif

struct SegvInstall {
    SegvInstall() {
        struct sigaction sa{};
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGSEGV, &sa, nullptr);
    }
} segv_install_guard;

#endif // _WIN32

int main(int argc, char* argv[])
{
    const char* infile = nullptr;
    unsigned disasm_flags = 0;
    bool unitbuf = false;
    bool banner = true;
    std::ofstream dc_out_file;
    std::ofstream das_out_file;

    for (int arg = 1; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--pycode-extra") == 0) {
            disasm_flags |= Pyc::DISASM_PYCODE_VERBOSE;
        } else if (strcmp(argv[arg], "--show-caches") == 0) {
            disasm_flags |= Pyc::DISASM_SHOW_CACHES;
        } else if (strcmp(argv[arg], "--help") == 0 || strcmp(argv[arg], "-h") == 0) {
            fprintf(stderr, "Usage:  %s [options] input.1shot.seq\n\n", argv[0]);
            fputs("Options:\n", stderr);
            fputs("  --pycode-extra Show extra fields in PyCode object dumps\n", stderr);
            fputs("  --show-caches  Don't suprress CACHE instructions in Python 3.11+ disassembly\n", stderr);
            fputs("  --unitbuf      Set output streams to be unbuffered\n", stderr);
            fputs("  --no-banner    Don't output banner\n", stderr);
            fputs("  --help         Show this help text and then exit\n", stderr);
            return 0;
        } else if (strcmp(argv[arg], "--unitbuf") == 0) {
            unitbuf = true;
        } else if (strcmp(argv[arg], "--no-banner") == 0) {
            banner = false;
        } else if (argv[arg][0] == '-') {
            fprintf(stderr, "Error: Unrecognized argument %s\n", argv[arg]);
            return 1;
        } else if (!infile) {
            infile = argv[arg];
        } else {
            fprintf(stderr, "Error: Only one input file allowed, got %s and %s\n",
                infile, argv[arg]);
            return 1;
        }
    }

    if (!infile) {
        fputs("No input file specified\n", stderr);
        return 1;
    }

    std::string prefix_name;
    const char *prefix_name_pos = strstr(infile, ".1shot.seq");
    if (prefix_name_pos == NULL) {
        prefix_name = infile;
    } else {
        prefix_name = std::string(infile, prefix_name_pos - infile + 6);
    }

    dc_out_file.open(prefix_name + ".cdc.py", std::ios_base::out);
    if (unitbuf) {
        dc_out_file.setf(std::ios::unitbuf);
    }
    if (dc_out_file.fail()) {
        fprintf(stderr, "Error opening file '%s' for writing\n", (prefix_name + ".cdc.py").c_str());
        return 1;
    }

    das_out_file.open(prefix_name + ".das", std::ios_base::out);
    if (unitbuf) {
        das_out_file.setf(std::ios::unitbuf);
    }
    if (das_out_file.fail()) {
        fprintf(stderr, "Error opening file '%s' for writing\n", (prefix_name + ".das").c_str());
        return 1;
    }

#ifdef __cpp_lib_fstream_native_handle
#ifndef _WIN32
    g_dc_fd  = dc_out_file.native_handle();
    g_das_fd = das_out_file.native_handle();
#else
    // Extract underlying handles to flush on exceptions
    // MSVC's native_handle is typically a HANDLE; MinGW may return a fd, requiring conversion via _get_osfhandle
    auto dc_nh  = dc_out_file.native_handle();
    auto das_nh = das_out_file.native_handle();
    using native_handle_t = decltype(dc_nh);
    if constexpr (std::is_same_v<native_handle_t, HANDLE>) {
        g_dc_h  = dc_nh;
        g_das_h = das_nh;
    } else if constexpr (std::is_integral_v<native_handle_t>) {
        intptr_t dc_handle = _get_osfhandle(dc_nh);
        if (dc_handle != -1 && dc_handle != reinterpret_cast<intptr_t>(INVALID_HANDLE_VALUE)) {
            g_dc_h = reinterpret_cast<HANDLE>(dc_handle);
        }
        intptr_t das_handle = _get_osfhandle(das_nh);
        if (das_handle != -1 && das_handle != reinterpret_cast<intptr_t>(INVALID_HANDLE_VALUE)) {
            g_das_h = reinterpret_cast<HANDLE>(das_handle);
        }
    } else {
        // ignore, keep as INVALID_HANDLE_VALUE
    }
#endif
#endif

    PycModule mod;
    try {
        mod.loadFromOneshotSequenceFile(infile);
    } catch (std::exception &ex) {
        fprintf(stderr, "Error disassembling %s: %s\n", infile, ex.what());
        return 1;
    }

    if (!mod.isValid()) {
        fprintf(stderr, "Could not load file %s\n", infile);
        return 1;
    }

    const char* dispname = strrchr(infile, PATHSEP);
    dispname = (dispname == NULL) ? infile : dispname + 1;
    const char* disp_prefix = strrchr(prefix_name.c_str(), PATHSEP);
    disp_prefix = (disp_prefix == NULL) ? prefix_name.c_str() : disp_prefix + 1;

    banner && formatted_print(
        das_out_file,
        R"(# File: %s (Python %d.%d)
# Disassembly generated by Pyarmor-Static-Unpack-1shot (%s), powered by pycdas

# ================================
# Pyarmor notes:
# - Pyarmor bytecode and code objects match standard Python, but special calls to Pyarmor runtime functions exist.
# - Calls on strings are not mistakes but markers, which are processed by Pyarmor at runtime.
#
# Decompilation guidance (without runtime):
# 1. Ignore encrypted bytes after `#`; use only the string before `#`.
# 2. Remove `"__pyarmor_enter_xxx__"(b"<COAddr>...")` and `"__pyarmor_leave_xxx__"(b"<COAddr>...")` (prologue/epilogue).
# 3. `"__pyarmor_assert_xxx__"(A)` is not a real assert statement.
#    - If `A` is a name or readable string: replace with `A`.
#    - If `A` is `(X, "Y")`: replace with `X.Y`.
#    - If `A` is `(X, "Y", Z)`: replace with `X.Y = Z`.
#    - Otherwise: choose the most reasonable replacement.
# 4. `"__pyarmor_bcc_xxx__"(...)` indicates native code; function body is not available. Add a comment.
# ================================

)",
        dispname,
        mod.majorVer(),
        mod.minorVer(),
        VERSION
    );
    try {
        output_object(mod.code().try_cast<PycObject>(), &mod, 0, disasm_flags,
        das_out_file);
    } catch (std::exception& ex) {
        fprintf(stderr, "Error disassembling %s: %s\n", infile, ex.what());
        das_out_file.flush();
        das_out_file.close();
        return 1;
    }

    das_out_file.flush();
    das_out_file.close();

    banner && formatted_print(
        dc_out_file,
        R"(# File: %s (Python %d.%d)
# Source generated by Pyarmor-Static-Unpack-1shot (%s), powered by Decompyle++ (pycdc)

# Note: Decompiled code can be incomplete and incorrect.
# Please also check the correct and complete disassembly file: %s.das

)",
        dispname,
        mod.majorVer(),
        mod.minorVer(),
        VERSION,
        disp_prefix
    );
    try {
        decompyle(mod.code(), &mod, dc_out_file);
    } catch (std::exception& ex) {
        fprintf(stderr, "Error decompyling %s: %s\n", infile, ex.what());
        dc_out_file.flush();
        dc_out_file.close();
        return 1;
    }

    dc_out_file.flush();
    dc_out_file.close();

    return 0;
}
