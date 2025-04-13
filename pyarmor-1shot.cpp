/** I want to use functions in pycdas.cpp directly, but not moving them to
 * another file, to sync with upstream in the future easily.
 */
#define main pycdas_main
# include "pycdas.cpp"
#undef main

#include "ASTree.h"

// Mode name getters to improve output
const char* get_pyarmor_mode_name(int mode)
{
    switch (mode) {
        case 0: return "Standard";
        case 1: return "Advanced";
        case 2: return "Super";
        case 3: return "VM+Advanced";
        case 4: return "VM+Super";
        case 5: return "BCC";
        default: return "Unknown";
    }
}

int main(int argc, char* argv[])
{
    const char* infile = nullptr;
    unsigned disasm_flags = 0;
    std::ofstream dc_out_file;
    std::ofstream das_out_file;
    bool silent_mode = false;

    for (int arg = 1; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--pycode-extra") == 0) {
            disasm_flags |= Pyc::DISASM_PYCODE_VERBOSE;
        } else if (strcmp(argv[arg], "--show-caches") == 0) {
            disasm_flags |= Pyc::DISASM_SHOW_CACHES;
        } else if (strcmp(argv[arg], "--silent") == 0) {
            silent_mode = true;
        } else if (strcmp(argv[arg], "--help") == 0 || strcmp(argv[arg], "-h") == 0) {
            fprintf(stderr, "Usage:  %s [options] input.1shot.seq\n\n", argv[0]);
            fputs("Options:\n", stderr);
            fputs("  --pycode-extra Show extra fields in PyCode object dumps\n", stderr);
            fputs("  --show-caches  Don't suprress CACHE instructions in Python 3.11+ disassembly\n", stderr);
            fputs("  --silent       Suppress most error messages\n", stderr);
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
        if (!silent_mode) {
            fprintf(stderr, "Error disassembling %s: %s\n", infile, ex.what());
        }
        return 1;
    }

    if (!mod.isValid()) {
        if (!silent_mode) {
            fprintf(stderr, "Could not load file %s\n", infile);
        }
        return 1;
    }
    
    // Handle BCC mode
    if (mod.isBccMode()) {
        if (!silent_mode) {
            fprintf(stderr, "BCC Mode detected for %s - using special handling\n", infile);
        }
        
        // For BCC mode, we should write a special note in the output files
        dc_out_file << "# This is a BCC (Byte Code Conversion) obfuscated file\n";
        dc_out_file << "# Some parts of the code were compiled to machine code and cannot be decompiled\n";
        dc_out_file << "# Only providing the available Python bytecode\n\n";
        
        das_out_file << "# This is a BCC (Byte Code Conversion) obfuscated file\n";
        das_out_file << "# Some parts of the code were compiled to machine code and cannot be disassembled\n";
        das_out_file << "# Only showing the available Python bytecode\n\n";
    }

    const char* dispname = strrchr(infile, PATHSEP);
    dispname = (dispname == NULL) ? infile : dispname + 1;

    formatted_print(das_out_file, "%s (Python %d.%d%s, PyArmor %s Mode)\n", dispname,
                    mod.majorVer(), mod.minorVer(),
                    (mod.majorVer() < 3 && mod.isUnicode()) ? " -U" : "",
                    get_pyarmor_mode_name(mod.pyarmorMode()));
    try {
        output_object(mod.code().try_cast<PycObject>(), &mod, 0, disasm_flags,
        das_out_file);
    } catch (std::exception& ex) {
        if (!silent_mode && !mod.isBccMode()) {
            fprintf(stderr, "Error disassembling %s: %s\n", infile, ex.what());
        }
        return mod.isBccMode() ? 0 : 1; // Return success for BCC mode despite errors
    }

    das_out_file.flush();
    das_out_file.close();

    dc_out_file << "# Source Generated with Decompyle++\n";
    formatted_print(dc_out_file, "# File: %s (Python %d.%d%s, PyArmor %s Mode)\n\n", dispname,
                    mod.majorVer(), mod.minorVer(),
                    (mod.majorVer() < 3 && mod.isUnicode()) ? " Unicode" : "",
                    get_pyarmor_mode_name(mod.pyarmorMode()));
    try {
        decompyle(mod.code(), &mod, dc_out_file);
    } catch (std::exception& ex) {
        if (!silent_mode && !mod.isBccMode()) {
            fprintf(stderr, "Error decompyling %s: %s\n", infile, ex.what());
        }
        return mod.isBccMode() ? 0 : 1; // Return success for BCC mode despite errors
    }

    dc_out_file.flush();
    dc_out_file.close();

    return 0;
}
