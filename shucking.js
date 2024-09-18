function main() {
  const libart = Module.enumerateSymbols("libart.so");

  const dexFileSizeSet = new Set();

  // art/runtime/class_linker.cc
  // ClassLinker::LoadMethod()
  for (const item of libart) {
    if (item.name.includes("LoadMethod")) {
      console.log(JSON.stringify(item));
      const targetFuncAddr = item.address;
      Interceptor.attach(targetFuncAddr, {
        // 第一个参数是DexFile对象
        onEnter: function(args) {
          // 这里是args[1] 因为args[0]表示ClassLinker 本身
          const dexFilePtr = ptr(args[1]);
          const pointerSize = Process.pointerSize;
          const base = dexFilePtr.add(pointerSize).readPointer();
          const size = dexFilePtr.add(pointerSize * 2).readUInt();
          // 大小相同的DexFile只dump一次
          if (!dexFileSizeSet.has(size)) {
            dexFileSizeSet.add(size);
            //console.log(`DexFile base: ${hexdump(base, { length: size })}`);
            console.log(`[Dump DexFile] base: ${base}, length: ${size}.`)
            dumpDexFile(base, size);
          }
        },
        //onLeave: function(retval) {
        //  console.log(`Leaving ${item.name} with retval: ${JSON.stringify(retval)}`);
        //}
      });
    }
  }

}

// 需要先授予应用存储权限
function dumpDexFile(base, size) {
  const path = `/sdcard/Download/${size}.dex`;
  const file = new File(path, "wb");
  file.write(base.readByteArray(size));
  file.flush();
  file.close();
}

setImmediate(main);
