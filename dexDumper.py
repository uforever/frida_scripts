import os
import sys
import glob
import time
import frida

package_name = ""


def on_message(message, data):
    if message['type'] == 'send':
        if package_name == "":
            return
        dex_file_name = f"{message['payload']}.dex"
        dex_file_path = os.path.join(os.getcwd(), package_name, dex_file_name)
        with open(dex_file_path, "wb") as f:
            f.write(data)


jscode = """
const dexFilePtrSet = new Set();
const sizeSet = new Set();
const pointerSize = Process.pointerSize;

function dumpDexFile(dexFilePtr) {
  // 每个地址只调用一次 不一定正确
  // 有可能函数回填后地址相同 有需要的话可能得验证一下
  const addressString = dexFilePtr.toString();
  if (dexFilePtrSet.has(addressString)) {
    return;
  }
  dexFilePtrSet.add(addressString);

  if (addressString === "0x0") {
    return;
  }

  const base = dexFilePtr.add(pointerSize).readPointer();
  const size = dexFilePtr.add(pointerSize * 2).readUInt();

  // size 至少 112+32
  if (size < 144) {
    return;
  }

  // 比较 DexFile 对象的 size 和 dex 文件二进制中的 file_size 是否相等
  const sizeBytes = dexFilePtr.add(pointerSize * 2).readByteArray(4);
  const fileSizeBytes = base.add(0x20).readByteArray(4);

  if (sizeBytes[0] !== fileSizeBytes[0]) return;
  if (sizeBytes[1] !== fileSizeBytes[1]) return;
  if (sizeBytes[2] !== fileSizeBytes[2]) return;
  if (sizeBytes[3] !== fileSizeBytes[3]) return;

  // 相同大小只调用一次
  if (sizeSet.has(size)) {
    return;
  }
  sizeSet.add(size);

  console.log(`\\n[*] Dump DexFile\\n- base: ${base}\\n- length: ${size}`);

  const data = base.readByteArray(size);
  send(size, data);
}

function main() {
  Java.perform(doJavaHook);

  // adb pull /apex/com.android.art/lib64/libart.so
  const libart = Process.findModuleByName("libart.so");
  const libartSymbols = Module.enumerateSymbols("libart.so");

  for (const symbol of libartSymbols) {
    if (!symbol.name.includes("DexFile")) {
      continue;
    }

    if (!symbol.name.includes("ClassLinker")) {
      continue;
    }

    // 下面两个函数就先不hook了
    if (symbol.name.includes("RegisterDexFileLocked")) {
      continue;
    }
    if (symbol.name.includes("RegisterDexFiles")) {
      continue;
    }

    // if (symbol.name.includes("LoadMethod")) {
    //   console.log(`\\n[!] Function hooked\\n- name: ${symbol.name}\\n- offset: ${symbol.address.sub(libart.base)}`);
    //   const targetFuncAddr = symbol.address;
    //   Interceptor.attach(targetFuncAddr, {
    //     onEnter: function (args) {
    //       const dexFilePtr = ptr(args[1]);
    //       dumpDexFile(dexFilePtr);
    //     },
    //   });
    // }

    if (symbol.name.includes("RegisterDexFile")) {
      console.log(`\\n[!] Function hooked\\n- name: ${symbol.name}\\n- offset: ${symbol.address.sub(libart.base)}`);
      const targetFuncAddr = symbol.address;
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          const dexFilePtr = ptr(args[1]);
          dumpDexFile(dexFilePtr);
        },
      });
    }
  }
}

function doJavaHook() {
  // const DexPathList = Java.use("dalvik.system.DexPathList");
  // DexPathList.$init.overload('java.lang.ClassLoader', 'java.lang.String', 'java.lang.String', 'java.io.File', 'boolean').implementation = function (definingContext, dexPath, librarySearchPath, optimizedDirectory, isTrusted) {
  //   console.log(`\\n[*] dalvik.system.DexPathList.$init called\\n- dexPath: ${dexPath}`);
  //   return this.$init(definingContext, dexPath, librarySearchPath, optimizedDirectory, isTrusted);
  // }

  // hook 下面这个就够了
  const DexFile = Java.use("dalvik.system.DexFile");
  DexFile.openDexFileNative.implementation = function (sourceName, outputName, flags, loader, elements) {
    console.log(`\\n[*] dalvik.system.DexFile.openDexFileNative called\\n- sourceName: ${sourceName}`);
    return this.openDexFileNative(sourceName, outputName, flags, loader, elements);
  }

  // console.log("\\n[!] Java function hooked\\n- dalvik.system.DexPathList.$init()\\n+ dalvik.system.DexFile.openDexFileNative()");
  console.log("\\n[!] Java function hooked\\n+ dalvik.system.DexFile.openDexFileNative()");
}

setImmediate(main);
"""

# usage: python dexDumper.py com.example.app
if __name__ == '__main__':
    try:
        package_name = sys.argv[1]
    except IndexError:
        print("Usage: python dexDumper.py package_name")
        sys.exit(1)

    # 查看当前目录下是否有package_name文件夹，如果没有则创建
    # 如果有则清空文件夹
    if os.path.exists(package_name):
        dex_files = glob.glob(os.path.join(package_name, '*.dex'))
        for dex_file in dex_files:
            os.remove(dex_file)
    else:
        os.makedirs(package_name)

    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    process = device.attach(pid)

    script = process.create_script(jscode)
    script.on('message', on_message)
    print('Running DexDumper')
    script.load()

    time.sleep(2)
    device.resume(pid)
    sys.stdin.read()
