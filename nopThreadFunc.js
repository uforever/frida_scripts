let msaoaidAlreadyHook = false; // 防止多次hook

// 两种nop函数的方式 之一 两种方式都能用
function nopFunc(parg2) {
  Memory.protect(parg2, 4, 'rwx'); // 修改该地址的权限为可读可写
  const writer = new Arm64Writer(parg2);
  writer.putRet(); // 直接 ret 不返回值
  writer.flush(); // 写入操作刷新到目标内存
  writer.dispose(); // 释放 Arm64Writer 使用的资源
  console.log("nopFunc" + parg2 + " success");
}

// 两种nop函数的方式 之二 两种方式都能用
function nop(base, offset) {
  Interceptor.replace(base.add(offset), new NativeCallback(function () {
    console.log(`thread func sub_${offset.toString(16).toUpperCase()} noped`)
  }, 'void', []));
}

function hookMsaoaidInitProc() {
  const linker = (Process.pointerSize == 8) ? Process.findModuleByName("linker64") : Process.findModuleByName("linker");
  if (linker) {
    // hook call_constructors 函数
    const symbols = linker.enumerateSymbols();
    for (const symbol of symbols) {
      if (symbol.name.includes("call_constructors")) {
        Interceptor.attach(symbol.address, {
          onEnter: function (_args) {
            if (!msaoaidAlreadyHook) {
              const targetSo = Process.findModuleByName("libmsaoaidsec.so");
              if (targetSo) {
                // hook libmsaoaidsec.so start
                nop(targetSo.base, 0x175f8);
                nop(targetSo.base, 0x16d30);
                // hook libmsaoaidsec.so end
                msaoaidAlreadyHook = true;
              }
            }
          }
        });
        break;
      }
    }
  }
}

function main() {
  const adeAddr = Module.findExportByName(null, "android_dlopen_ext");
  Interceptor.attach(adeAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        console.log("[dylib open]: ", path);

        if (path.includes("libDexHelper.so")) {
          this.isBang = true;
        }
        if (path.includes("libmsaoaidsec.so")) {
          hookMsaoaidInitProc(); // msaoaid 在加载过程中就进行了检测 需要提前hook
        }
      }
    },
    onLeave: function () {
      if (this.isBang) {
        const bangBase = Module.findBaseAddress("libDexHelper.so");
        nopFunc(bangBase.add(0x4b3ec));
        nopFunc(bangBase.add(0x58990));
        nopFunc(bangBase.add(0x512f8));
        nopFunc(bangBase.add(0x596e0));
        nopFunc(bangBase.add(0x5e144));
      }
    },
  });
}

setImmediate(main);
