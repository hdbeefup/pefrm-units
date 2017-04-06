# PE File PDB Symbol Injector

Use this program to put debug symbols from an IDA database into a PDB database,
so that other debuggers like Visual Studio can display debug information.

* GTAForums topic: http://gtaforums.com/topic/870170-idb-to-visual-studio-symbol-injection/
* YouTube video: https://www.youtube.com/watch?v=Vn9YNqm5ny0

Wish to contribute? Contact me at wordwhirl@outlook.de for details.

You should use dumpinfo.idc to generate the "symbols.txt" file that is required
to patch in symbols. You can get it here:
https://www.hex-rays.com/products/ida/support/freefiles/dumpinfo.idc

The tool has to be launched through Visual Studio to work. Otherwise it will
not find the necessary "MSPDBCORE.DLL".