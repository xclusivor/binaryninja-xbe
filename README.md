binaryninja-xbe
==========
Xbox Executable (XBE) Loader plugin for [Binary Ninja](https://binary.ninja/)

This will download and execute the [XbSymbolDatabase](https://github.com/Cxbx-Reloaded/XbSymbolDatabase) analyzer for library symbol recovery.

Installation
--------------
Clone this repo into your Binary Ninja plugin directory.

You can manually install the symbol analyzer by extracting it the into root of the plugins directory.
e.g. `$XBE_PLUGIN_DIR/XbSymbolDatabase/linux_x64/bin/XbSymbolDatabaseCLI`

Credits
--------------
Inspired by [ghidra-xbe](https://github.com/XboxDev/ghidra-xbe/tree/master)