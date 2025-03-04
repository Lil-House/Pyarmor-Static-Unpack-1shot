/** I want to use functions in pycdas.cpp directly, but not moving them to
 * another file, to sync with upstream in the future easily.
 */
#define main pycdas_main
# include "pycdas.cpp"
#undef main

#include "ASTree.h"

int main(int argc, char* argv[])
{
    const char* infile = nullptr;
    unsigned disasm_flags = 0;
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
            fputs("  --help         Show this help text and then exit\n", stderr);
            return 0;
        } else if (argv[arg][0] == '-') {
            fprintf(stderr, "Error: Unrecognized argument %s\n", argv[arg]);
            return 1;
        } else {
            infile = argv[arg];
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
    if (dc_out_file.fail()) {
        fprintf(stderr, "Error opening file '%s' for writing\n", (prefix_name + ".cdc.py").c_str());
        return 1;
    }

    das_out_file.open(prefix_name + ".das", std::ios_base::out);
    if (das_out_file.fail()) {
        fprintf(stderr, "Error opening file '%s' for writing\n", (prefix_name + ".das").c_str());
        return 1;
    }

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

    formatted_print(das_out_file, "%s (Python %d.%d%s)\n", dispname,
                    mod.majorVer(), mod.minorVer(),
                    (mod.majorVer() < 3 && mod.isUnicode()) ? " -U" : "");
    try {
        output_object(mod.code().try_cast<PycObject>(), &mod, 0, disasm_flags,
        das_out_file);
    } catch (std::exception& ex) {
        fprintf(stderr, "Error disassembling %s: %s\n", infile, ex.what());
        return 1;
    }

    dc_out_file << "# Source Generated with Decompyle++\n";
    formatted_print(dc_out_file, "# File: %s (Python %d.%d%s)\n\n", dispname,
                    mod.majorVer(), mod.minorVer(),
                    (mod.majorVer() < 3 && mod.isUnicode()) ? " Unicode" : "");
    try {
        decompyle(mod.code(), &mod, dc_out_file);
    } catch (std::exception& ex) {
        fprintf(stderr, "Error decompyling %s: %s\n", infile, ex.what());
        return 1;
    }

    return 0;
}
