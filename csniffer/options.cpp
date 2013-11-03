#include <stdlib.h>
#include <iostream>
#include "optionparser.h"
#include "options.h"

const option::Descriptor usage[] =
{
    {UNKNOWN,     0,"" , "",              option::Arg::None,        "USAGE: cap [options]\n\n"
                                                                    "Options:" },
    {HELP,        0,"" , "help",          option::Arg::None,        "  --help  \tPrint usage and exit." },
    {IFACE,       0,"i", "iface",         option::Arg::Optional,    "  --iface=I, -iI  \tInterface to listen on" },
    {FILTER,      0,"f", "filter",        option::Arg::Optional,    "  --filter=F, -fF  \tpcap filter to use" },
    {STATSD,      0,"s", "statsd",        option::Arg::Optional,    "  --statsd=H:P, \thost:port of statsd" },
    {MULTIPLY,    0,"m", "multiply",      option::Arg::Optional,    "  --multiply=M, \tmultiply traffic" },
    {RPSLIMIT,    0,"r", "rpslimit",      option::Arg::Optional,    "  --rpslimit=L, \tlimit RPS to this number" },
    {PRINT,       0,"",  "print",         option::Arg::None,        "  --print, \tprint intercepted messages" },
    {REPLAY,      0,"r", "replay-socket", option::Arg::Optional,    "  --replay-socket=S, \tbase name of unix dgram sockets in the pool" },
    {REPLAYCOUNT, 0,"",  "pool-size",     option::Arg::Optional,    "  --pool-size=N, \tsize of the replay pool" },
    {UNKNOWN,     0,"" ,  "",             option::Arg::None,        "\nExamples:\n"
                                                                   "  ./cap --iface=eth1 --filter='tcp dst port 80'\n"},
    {0,0,0,0,0,0}
};

option::Option options[MAXOPTIONS];

void parse_options(int argc, char **argv) {
    argc-=(argc>0); argv+=(argc>0); // skip program name argv[0] if present
    option::Stats  stats(usage, argc, argv);
    option::Option buffer[stats.buffer_max];
    option::Parser parse(usage, argc, argv, options, buffer);

    if (parse.error()) {
        exit(1);
    }

    if (options[HELP] || argc == 0) {
        option::printUsage(std::cout, usage);
        exit(0);
    }

    int unk_options_count = 0;
    for (option::Option* opt = options[UNKNOWN]; opt; opt = opt->next()) {
        std::cout << "Unknown option: " << opt->name << "\n";
        unk_options_count++;
    }
    for (int i = 0; i < parse.nonOptionsCount(); ++i) {
        std::cout << "Non-option #" << i << ": " << parse.nonOption(i) << "\n";
        unk_options_count++;
    }

    if (unk_options_count > 0) {
        exit(1);
    }
}

