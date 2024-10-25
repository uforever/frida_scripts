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
  const addressString = dexFilePtr.toString();
  if (dexFilePtrSet.has(addressString)) {
    return;
  }
  dexFilePtrSet.add(addressString);

  if (addressString === "0x0") {
    return;
  }

  // try {
  const base = dexFilePtr.add(pointerSize).readPointer();
  const size = dexFilePtr.add(pointerSize * 2).readUInt();

  // size 至少 112+32
  if (size < 144) {
    return;
  }

  const sizeBytes = dexFilePtr.add(pointerSize * 2).readByteArray(4);
  const fileSizeBytes = base.add(0x20).readByteArray(4);

  if (
    sizeBytes[0] !== fileSizeBytes[0] ||
    sizeBytes[1] !== fileSizeBytes[1] ||
    sizeBytes[2] !== fileSizeBytes[2] ||
    sizeBytes[3] !== fileSizeBytes[3]
  ) {
    return;
  }

  // if (sizeSet.has(size)) {
  //   return;
  // }
  // sizeSet.add(size);

  console.log(`[*] Dump DexFile - base: ${base}, length: ${size}.`)
  const data = base.readByteArray(size);
  send(size, data);

  // } catch (err) {
  //   console.error(err);
  // }
}

function main() {
  Java.perform(doJavaHook);

  const libart = Module.enumerateSymbols("libart.so");

  for (const item of libart) {
    if (!item.name.includes("DexFile")) {
      continue;
    }
    if (item.name.includes("LoadMethod")) {
      console.log(JSON.stringify(item));
      const targetFuncAddr = item.address;
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          const dexFilePtr = ptr(args[1]);
          dumpDexFile(dexFilePtr);
        },
      });
    } else if (item.name.includes("LoadClass")) {
      console.log(JSON.stringify(item));
      const targetFuncAddr = item.address;
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          const dexFilePtr = ptr(args[2]);
          dumpDexFile(dexFilePtr);
        },
      });
    }
  }
}

function doJavaHook() {
  const DexPathList = Java.use("dalvik.system.DexPathList");
  console.log("DexPathList hooked");

  DexPathList.loadDexFile.implementation = function (file, optimizedDirectory, loader, elements) {
    const retval = this.loadDexFile(file, optimizedDirectory, loader, elements);

    const mCookie = retval.mCookie.value;
    const Array = Java.use("java.lang.reflect.Array");
    const size = Array.getLength(mCookie);

    console.log(`[*] DexFile from ${retval.mCookie.holder}`);

    for (let i = 0; i < size; i++) {
      const longValue = Array.getLong(mCookie, i);
      const dexFilePtr = ptr(longValue);
      dumpDexFile(dexFilePtr);
    }
    return retval;
  }
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
    print('[*] Running DexDumper')
    script.load()

    time.sleep(2)
    device.resume(pid)
    sys.stdin.read()
