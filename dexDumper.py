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
        dex_file_path = os.path.join(
            os.getcwd(), package_name, message['payload'])
        with open(dex_file_path, "wb") as f:
            f.write(data)


jscode = """
const dexFilePtrSet = new Set();
const checksumSet = new Set();
const pointerSize = Process.pointerSize;

// 添加一些不需要dump的dex文件 如miui mediatek等
checksumSet.add(0x43174B52);
checksumSet.add(0x4480A281);
checksumSet.add(0x6186E805);
checksumSet.add(0x6BBD829E);
checksumSet.add(0x78CC0F74);
checksumSet.add(0x85DE015E);
checksumSet.add(0x8690AEE2);
checksumSet.add(0x93289A69);
checksumSet.add(0x9AB6A58A);
checksumSet.add(0x9ADDCFFD);
checksumSet.add(0xB214697F);
checksumSet.add(0xB5E8C542);
checksumSet.add(0xDD357319);
checksumSet.add(0xE7ECDFB6);
checksumSet.add(0xFB9676D7);

function dumpDexFileByBeginAndSize(begin, size) {
  // 相同校验和只dump一次
  const checksum = begin.add(8).readU32();
  if (checksumSet.has(checksum)) {
    return;
  }
  checksumSet.add(checksum);
  console.log(`\\n[*] Found DexFile\\n- begin: ${begin}\\n- size: ${size}`);

  const dexMagic = begin.readU32();
  if (dexMagic !== 0x0A786564) { // dex
    // 非dex文件打印一下头部信息
    // 0x78656463 cdex ...
    const headerHexDump = hexdump(begin, {
      offset: 0,
      length: 8,
      header: true,
      ansi: true
    });
    console.log(`[!] Not a dex file:\\n${headerHexDump}`);
    return;
  }

  const filename = `${checksum.toString(16).toUpperCase().padStart(8, '0')}.dex`;
  console.log(`=> Dump to ${filename}`);
  const data = begin.readByteArray(size);
  send(filename, data);
}

function dumpDexFileByPointer(dexFilePtr) {
  // 每个地址只调用一次 不一定正确
  // 有可能函数回填后地址相同 有需要的话关闭这里的判断
  const addressString = dexFilePtr.toString();
  if (dexFilePtrSet.has(addressString)) {
    return;
  }
  dexFilePtrSet.add(addressString);

  const begin = dexFilePtr.add(pointerSize).readPointer();
  const size = dexFilePtr.add(pointerSize * 2).readUInt();

  dumpDexFileByBeginAndSize(begin, size);
}

function main() {
  Java.perform(doJavaHook);

  // adb pull /apex/com.android.art/lib64/libart.so
  const libart = Process.findModuleByName("libart.so");
  const libartSymbols = Module.enumerateSymbols("libart.so");


  // OpenCommon 在较新系统上未经测试 关闭下面这一段 不影响使用
  // adb pull /apex/com.android.art/lib64/libdexfile.so
  // libdexfile.so中hook OpenCommon函数
  const libdexfile = Process.findModuleByName("libdexfile.so");
  const libdexfileSymbols = Module.enumerateSymbols("libdexfile.so");

  for (const symbol of libdexfileSymbols) {
    if (symbol.name.includes("OpenCommon")) {
      const targetFuncAddr = symbol.address;
      console.log(`\\n[+] Function hooked\\n- name: ${symbol.name}\\n- offset: ${targetFuncAddr.sub(libdexfile.base)}`);
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          // 名字包含 "OpenCommon" 的函数 可能不止一个
          // 所以此处前两个参数未必是 begin 和 size
          this.begin = ptr(args[0]);
          this.size = args[1].toInt32();
        },
        onLeave: function (_retval) {
          dumpDexFileByBeginAndSize(this.begin, this.size);
        }
      });
    }
  }

  // libart.so
  // RegisterDexFile函数 和 LoadMethod函数
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

    if (symbol.name.includes("RegisterDexFile")) {
      const targetFuncAddr = symbol.address;
      console.log(`\\n[+] Function hooked\\n- name: ${symbol.name}\\n- offset: ${targetFuncAddr.sub(libart.base)}`);
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          const dexFilePtr = ptr(args[1]);
          dumpDexFileByPointer(dexFilePtr);
        },
      });
    }

    if (symbol.name.includes("LoadMethod")) {
      const targetFuncAddr = symbol.address;
      console.log(`\\n[+] Function hooked\\n- name: ${symbol.name}\\n- offset: ${targetFuncAddr.sub(libart.base)}`);
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          const dexFilePtr = ptr(args[1]);
          dumpDexFileByPointer(dexFilePtr);
        },
      });
    }
  }
}

function doJavaHook() {
  // hook下面这个两个Java层函数
  const DexFile = Java.use("dalvik.system.DexFile");
  DexFile.openDexFileNative.implementation = function (sourceName, outputName, flags, loader, elements) {
    console.log(`\\n[*] dalvik.system.DexFile.openDexFileNative called\\n- sourceName: ${sourceName}`);
    return this.openDexFileNative(sourceName, outputName, flags, loader, elements);
  }

  // const ByteBuffer = Java.use("java.nio.ByteBuffer");

  DexFile.openInMemoryDexFilesNative.implementation = function (bufs, arrays, starts, ends, loader, elements) {
    // TODO: 通过这里的arrays参数dump文件
    console.log(`\\n[*] dalvik.system.DexFile.openInMemoryDexFilesNative called`);
    return this.openInMemoryDexFilesNative(bufs, arrays, starts, ends, loader, elements);
  }

  // console.log("\\n[!] Java function hooked\\n- dalvik.system.DexPathList.$init()\\n+ dalvik.system.DexFile.openDexFileNative()");
  console.log("\\n[+] Java function hooked\\n+ dalvik.system.DexFile.openDexFileNative()\\n+ dalvik.system.DexFile.openInMemoryDexFilesNative()");
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
