#!/usr/bin/env python3
#
# locate map operator [] reads
#
# Example usage of this addon (scan a sourcefile main.cpp)
# cppcheck --dump main.cpp
# python map-subscript-read.py main.cpp.dump

import cppcheckdata
import sys


DEBUG = ('-debug' in sys.argv)


def reportError(token, severity, msg, id):
    cppcheckdata.reportError(token, severity, msg, 'map', id)


def simpleMatch(token, pattern):
    return cppcheckdata.simpleMatch(token, pattern)


def check_map_subscript(data):
    #if data.language != 'cpp':
    #    return
    for cfg in data.iterconfigurations():
        for token in cfg.tokenlist:
            if token.str != '[' or token.astOperand1 is None or token.astOperand2 is None:
                continue
            if token.astParent and token.astParent.str == '=' and token.astParent.astOperand1 == token:
                continue
            m = token.astOperand1
            if m.variable is None:
                continue
            if simpleMatch(m.variable.typeStartToken, 'std :: map <'):
                reportError(token, 'style', 'Reading from std::map with subscript operator [].', 'mapSubscriptRead')
            elif simpleMatch(m.variable.typeStartToken, 'std :: unordered_map <'):
                reportError(token, 'style', 'Reading from std::unordered_map with subscript operator [].', 'mapSubscriptRead')


for arg in sys.argv[1:]:
    if arg == '--cli':
        continue
    data = cppcheckdata.CppcheckData(arg)
    check_map_subscript(data)

sys.exit(cppcheckdata.EXIT_CODE)
