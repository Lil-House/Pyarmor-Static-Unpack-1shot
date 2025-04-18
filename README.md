# Pyarmor Static Unpack One-Shot Tool

[Pyarmor](https://github.com/dashingsoft/pyarmor) is a popular tool to protect Python source code. It turns Python scripts into binary data, which can be regarded as an encrypted variant of pyc files. They can be decrypted by a shared library (pyarmor_runtime) and then executed by Python interpreter.

This project aims to convert armored data back to bytecode assembly and (experimentally) source code. We forked the awesome [Decompyle++](https://github.com/zrax/pycdc) (aka pycdc), and added some processes on it like modifying abstract syntax tree.

> [!WARNING]
>
> **Disassembly results are accurate, but decompiled code can be incomplete and incorrect.** [See issue #3](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/issues/3)

## Features

### Static

You don't need to execute the encrypted script. We decrypt them using the same algorithm as pyarmor_runtime. This is useful when the scripts cannot be trusted.

### Universal

Currently we are trying to support Pyarmor 8.0 to 9.1.3 (latest), Python 3.7 - 3.13, on all operating systems, with obfuscating options as many as possible. (However, we only have limited tests.)

You can run this tool in any environment, no need to be the same with obfuscated scripts or runtime.

> [!NOTE]
> 
> If the data starts with `PY` followed by six digits, it is supported. Otherwise, if it starts with `PYARMOR`, it is generated by Pyarmor 7 or earlier, and is not supported.

### Easy to use

The only thing you need to do is specifying where your obfuscated scripts are. The tool does everything like detecting armored data, parsing, disassembling, and decompiling. See "Usage" section below.

## Build

``` bash
mkdir build
cd build
cmake ..
cmake --build .
cmake --install .
```

You can also download prebuilt binary files on [releases page](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases).

## Usage

``` bash
python /path/to/helpers/shot.py /path/to/scripts
```

Before running `shot.py`, make sure the executable `pyarmor-1shot` (`pyarmor-1shot.exe` on Windows) exists in `helpers` directory.

You only need to specify the directory that contains all armored data and `pyarmor_runtime`. The tool finds and handles them recursively as much as possible.

When necessary, specify a `pyarmor_runtime` executable with `-r path/to/pyarmor_runtime[.pyd|.so|.dylib]`.

All files generated from this tool have a `.1shot.` in file names. If you want to save them in another directory instead of in-place, use `-o another/path/`. Folder structure will remain unchanged.

Note:

- Subdirectories will not be touched if the folder name is exactly `__pycache__` or `site-packages` or it directly contains a file named `.no1shot`, and symbolic links will not be followed, to avoid repeat or forever loop and save time. If you really need them, run the script later in these directories and specify the runtime.
- Archives, executables generated by PyInstaller and so on, must be unpacked by other tools before decrypting, or you will encounter undefined behavior.

## Feedback

Feel free to open an issue if you have any questions, suggestions, or problems. Don't forget to attach the armored data and the `pyarmor_runtime` executable if possible.

## Todo (PR Welcome!)

- [ ] Multi-platform pyarmor_runtime executable
- [ ] Support more obfuscating options
- [ ] Regenerate pyc for other backends
