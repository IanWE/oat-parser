// OATLoaderDumper.cpp : Defines the entry point for the console application.
//

#include "StringPiece.h"
#include "oatparser.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <iostream>

static void usage() {
    fprintf(stderr,
            "Usage: oatparser [options] ...\n"
                    "    Example: oatparser --read-file=base.odex -m=0-0-0\n"
                    "\n");
}

static bool IsDirExist(const std::string &outpath) {
    bool ret = true;

    if (-1 == access(outpath.c_str(), F_OK) && errno == ENOENT) {
        ret = false;
    }

    return ret;
}

static bool MakeDir(const std::string &outpath) {
    bool ret = false;
    if (0 == mkdir(outpath.c_str(), 0400 | 0200)) {
        ret = true;
    }

    return ret;
}

int main(int argc, char *argv[]) {
    argv++;
    argc--;

    if (argc == 0) {
        fprintf(stderr, "No arguments specified.\n");
        usage();
        return false;
    }

    using namespace Art;
    std::string oat_file; //--oat-file=
    std::string oat_todex_path; //--out-path=
    std::string securestore_file; //--secure-file=
    bool isVerification = false;
    std::string read_file;
    std::string tamper_file;
    std::string c_;
    for (int i = 0; i < argc; i++) {
        const StringPiece option(argv[i]);
        if (option.starts_with("--read-file")) {
            read_file = option.substr(strlen("--read-file=")).data();
        }
	if (option.starts_with("--m"))
	    c_ = option.substr(strlen("--m=")).data();
    }

     if (!ParseOatFile(read_file,c_)) {
            std::cout << "Failed to parse oat file: " << read_file << std::endl;
            return false;
      }
    return 0;
}

