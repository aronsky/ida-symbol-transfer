import argparse
import pickle
import json
import sys

class Function(dict):
    def __init__(self, ea):
        # Address
        self['addr'] = self._addr = ea

        # Name (if user-defined)
        self['name'] = self._name = idc.GetFunctionName(ea)

        # Function end
        self['end'] = self._end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)

        # Flags
        self['flags'] = self._flags = idc.GetFunctionFlags(ea)

        # Comments
        self['rep_cmt'] = self._rep_cmt = idc.GetFunctionCmt(ea, True)
        self['non_rep_cmt'] = self._non_rep_cmt = idc.GetFunctionCmt(ea, False)

class Name(dict):
    def __init__(self, ea, name):
        # Address
        self['addr'] = self._addr = ea

        # Name
        self['name'] = self._name = name
    

def ExportFunctionsFromIDA(outfile):
    functions = [Function(addr) for addr in idautils.Functions(MinEA(), MaxEA())]

    if not functions:
        idc.Message("No functions found!\n")
        return

    pickle.dump(functions, outfile)

    idc.Message("Exported {} functions!\n".format(len(functions)))

def ExportNamesFromIDA(outfile):
    names = [Name(addr, name) for addr, name in idautils.Names()]

    if not names:
        idc.Message("No names found!\n")
        return

    pickle.dump(names, outfile)

    idc.Message("Exported {} names!".format(len(names)))

def ImportFunctionsIntoIDA(infile):
    functions = [obj for obj in pickle.load(infile) if obj is Function]

    for function in functions:
        idc.MakeFunction(function._addr)

        if not function._name.startswith("sub_") and not function._name.startswith("nullsub_"):
            idc.MakeName(function._addr, str(function._name))

        idc.SetFunctionFlags(function._addr, function._flags)
        idc.SetFunctionCmt(function._addr, str(function._rep_cmt), True)
        idc.SetFunctionCmt(function._addr, str(function._non_rep_cmt), False)

    idc.Message("Imported {} functions!\n".format(len(functions)))

def ImportNamesIntoIDA(infile):
    name = [obj for obj in pickle.load(infile) if obj is Name]

    for function in functions:
        idc.MakeFunction(function._addr)

        if not name._name.startswith("sub_") and not name._name.startswith("nullsub_"):
            idc.MakeName(function._addr, str(function._name))

    idc.Message("Imported {} names!\n".format(len(functions)))

def PrintFunctionsInR2Format(infilename):
    with open(infilename, "rb") as infile:
        functions = pickle.load(infile)
    
    for function in functions:
        if not function._name.startswith("nullsub_"):
            if function._name.startswith("sub_"):
                function._name = function._name.replace("sub_", "fcn.")
            #print "afn %s 0x%x" % (function._name, function._addr)
            #function._name = "sym." + function._name
            print "f+%s %d @ 0x%x" % (function._name, function._end - function._addr, function._addr)
            print "af+ 0x%x 0x%x %s" % (function._addr, function._end - function._addr, function._name)
            print "afb+ 0x%x 0x%x 0x%x" % (function._addr, function._addr, function._end - function._addr)
            
def command_line_mode():
    parser = argparse.ArgumentParser(description="Parse pickled/JSONed IDB files")
    parser.add_argument('-p', '--pickle', required=True, help="The name of the pickled IDB file", metavar="pickle_filename")
    arguments = parser.parse_args()
    if arguments.pickle:
        PrintFunctionsInR2Format(arguments.pickle)
    else:
        parser.print_usage()
        sys.exit(1)

def ida_script_mode():
    userResponse = AskYN(1, "Export (Yes) / Import (No) / Do nothing (Cancel)")
    if 1 == userResponse:
        outfilename = AskFile(1, "*.pkl;*.json", "Export functions to file...")

        if not outfilename:
            idc.Message("No file selected!\n")
            return

        idc.Message("Exporing to {}...\n".format(outfilename))

        with open(outfilename, 'wb') as outfile:
            ExportFunctionsFromIDA(outfile)
            ExportNamesFromIDA(outfile)
    elif 0 == userResponse:
        infilename = AskFile(0, "*.pkl;*.json", "Import functions from file...")

        if not infilename:
            idc.Message("No file selected!\n")
            return

        idc.Message("Importing from {}...\n".format(infilename))

        with open(infilename, 'rb') as infile:
            ImportFunctionsIntoIDA(infile)
            ImportNamesIntoIDA(infile)

if __name__ == '__main__':
    try:
        import idautils
        import idc

        # Code was run as a script in IDA:
        ida_script_mode()
    except ImportError, ie:
        # Code was run from command line.
        command_line_mode()
