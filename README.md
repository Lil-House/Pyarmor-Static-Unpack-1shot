# Pyarmor-Static-Unpack-1shot

🚧 **Working in progress**

Generally this project aims to statically convert (without executing) armored data - which can be regarded as an encrypted variant of pyc files - back to disassembly and (experimentally) source code. Therefore we forked the awesome [Decompyle++](https://github.com/zrax/pycdc) (aka pycdc).

Currently we are trying to support Pyarmor 8.0 - latest (9.1.0), Python 3.7 - 3.13, platforms covering Windows, Linux, macOS, and Android, with obfuscating options as many as possible. (However, we only have limited tests.)

If the data starts with `PY` followed by six digits, it is supported. Otherwise, if it starts with `PYARMOR`, it is generated by Pyarmor 7 or before, and is not supported.

We cannot wait to make it public. Detailed write-up will be available soon. For those who are curious, temporarily you can check out [the similar work of G DATA Advanced Analytics](https://cyber.wtf/2025/02/12/unpacking-pyarmor-v8-scripts/).

## Build

``` bash
mkdir build
cd build
cmake ..
cmake --build .
mv pyarmor-1shot[.exe] ../helpers
```

## Usage

Make sure the executable `pyarmor-1shot` (`pyarmor-1shot.exe` on Windows) exists in `helpers` directory, and run `helpers/shot.py` in Python 3 (no need to use the same version with obfuscated scripts) with the "root" directory of obfuscated scripts. It will recursively find and handle `pyarmor_runtime` and as much armored data as possible. For example:

``` bash
$ ls /path/to/scripts
__pycache__  pyarmor_runtime_000000  obf_main.py  plain_src.py  util.pyc  packed.so  folder_with_other_scripts  readme.unrelated
$ python /path/to/helpers/shot.py /path/to/scripts
```

When necessary, specify a `pyarmor_runtime` executable with `-r path/to/pyarmor_runtime[.pyd|.so|.dylib]`.

All files generated from this tool have a `.1shot.` in file names. If you want to save them in another directory instead of in-place, use `-o another/path/`. Folder structure will remain unchanged.

Note:

- Subdirectories called `__pycache__` or `site-packages` will not be touched, and symbolic links will not be followed, to avoid repeat or forever loop and save time. If you really need them, run the script later in these directories (as "root" directory) and specify the runtime.
- Archives, executables generated by PyInstaller and so on, must be unpacked by other tools before decrypting, or you will encounter undefined behavior.

## Feedback

Feel free to open an issue if you have any questions, suggestions, or problems. Don't forget to attach the armored data and the `pyarmor_runtime` executable if possible.

## Todo (PR Welcome!)

- [ ] Write-up
- [ ] Multi-platform pyarmor_runtime executable
- [ ] Accept more input forms
- [ ] Tests for different Pyarmor and Python versions
- [ ] Support more obfuscating options
- [ ] Use asyncio for concurrency
- [ ] Pyarmor 7 and before (Later or never.)
