#ifndef OPTIONS_H
#define OPTIONS_H

#include "optionparser.h"

enum  optionIndex { 
    UNKNOWN, HELP, IFACE, FILTER, STATSD,
    PRINT, RPSLIMIT, MULTIPLY,
    REPLAY, REPLAYCOUNT,
    MAXOPTIONS};

void parse_options(int argc, char **argv);

extern option::Option options[MAXOPTIONS];

#endif
