import idc
import idautils
import pickle

class Function(dict):
    def __init__(self, ea):
        # Address
        self._addr = ea

        # Name (if user-defined)
        self._name = idc.GetFunctionName(ea)

        # Flags
        self._flags = idc.GetFunctionFlags(ea)

        # Comments
        self._rep_cmt = idc.GetFunctionCmt(ea, True)
        self._non_rep_cmt = idc.GetFunctionCmt(ea, False)
    

    @classmethod
    def ExportFunctions(cls):
        functions = [Function(addr) for addr in idautils.Functions(idc.MinEA(), idc.MaxEA())]

        if not functions:
            idc.Message("No functions found!\n")
            return

        outfilename = idc.AskFile(1, "*.pkl", "Export functions to file...") # 1 = Save

        if not outfilename:
            idc.Message("No file selected!\n")
            return

        with open(outfilename, "wb") as outfile:
            pickle.dump(functions, outfile)

        idc.Message("Exported %d functions to %s!\n" % (len(functions), outfilename))

    @classmethod
    def ImportFunctions(cls):
        infilename = idc.AskFile(0, "*.pkl", "Import functions from file...") # 0 = Open

        if not infilename:
            idc.Message("No file selected!\n")
            return

        with open(infilename, "rb") as infile:
            functions = pickle.load(infile)

        for function in functions:
            idc.MakeFunction(function._addr)

            if not function._name.startswith("sub_") and not function._name.startswith("nullsub_"):
                idc.MakeName(function._addr, str(function._name))

            idc.SetFunctionFlags(function._addr, function._flags)
            idc.SetFunctionCmt(function._addr, str(function._rep_cmt), True)
            idc.SetFunctionCmt(function._addr, str(function._non_rep_cmt), False)

        idc.Message("Imported %d functions from %s!\n" % (len(functions), infilename))


# User interaction code:
userResponse = idc.AskYN(1, "Export (Yes) / Import (No) / Do nothing (Cancel)")
if 1 == userResponse:
    Function.ExportFunctions()
elif 0 == userResponse:
    Function.ImportFunctions()
