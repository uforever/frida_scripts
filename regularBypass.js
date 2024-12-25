const packageName = "com.wodi.who";
const targetLibs = new Set([
  "libmsaoaidsec.so",
]);
// 自动生成重定向maps文件
// 可能会导致频繁IO 最好手动生成
const autoGenMaps = true;
const onlyHookTargetLibs = true;


// const tempFilePath = `/data/user/0/${packageName}/tempfile`;
const tempFilePath = `/data/data/${packageName}/tempfile`;
// 添加一些不需要hook的so
const soNameSet = new Set([
  "libandroid.so",
  "libbase.so",
  "libopenjdkjvmti.so",
  "libc.so",
  "libc++.so",
  "libstdc++.so",
  "libcutils.so",
  "libgui.so",
  "libui.so",
  "libdl.so",
  "libdexfile.so",
  "liblog.so",
  "libutils.so",
  "libexpat.so",
  "libm.so",
  "libart.so",
  "libart-compiler.so",
  "libart-dexlayout.so",
  "libartbase.so",
  "libartpalette.so",
  "libprofile.so",
  "libperfctl.so",
  "libEGL.so",
  "javalib.odex",
  "libz.so",
  "system@priv-app@RtMiCloudSDK@RtMiCloudSDK.apk@classes.dex",
  "android.hardware.graphics.mapper@4.0-impl-mediatek.so",
]);


const antiRoutines = {
  "libmsaoaidsec.so": [
    // 0x1c544,
    // 0x1b8d4,
    // 0x26e5c,
  ]
};
function main() {
  /*
  第一步需要定位so 确定是哪个so在反调试
  顺便看一下是在init中还是JNI_OnLoad之后
  */
  hookLibdl();
}

function patchLib(soName, base) {
  /*
  在目标库init前 对libc进行hook
  hook pthread_create 检测执行的线程
  绕过一些常见检测
  */
  hookPthreadCreate();
  for (const offset of antiRoutines[soName]) {
    Interceptor.replace(base.add(offset), new NativeCallback(() => { }, 'void', []));
  }
  // regularBypass(); // 通用绕过
}

function hasKeyword(str) {
  return str.includes("frida") ||
    str.includes(":69A2") ||
    str.includes("gum-js") ||
    str.includes("REJECT") ||
    str.includes("gmain") ||
    str.includes("gdbus") ||
    str.includes("linjector") ||
    str.includes("agent") ||
    str.includes("/data/local/tmp") ||
    str.includes("GLib-GIO") ||
    str.includes("GDBusProxy") ||
    str.includes("adb") ||
    str.includes("GumScript");
}

function replaceKeyword(str) {
  let result = str.replace(/TracerPid:\t\d+/g, "TracerPid:\t0");
  result = result.replaceAll("frida", "foo");
  result = result.replaceAll("gum-js", "");
  result = result.replaceAll("REJECT", "");
  result = result.replaceAll("gmain", "");
  result = result.replaceAll("gdbus", "");
  result = result.replaceAll("linjector", "");
  result = result.replaceAll("agent", "bar");
  result = result.replaceAll("/data/local/tmp", "/");
  result = result.replaceAll("GLib-GIO", "");
  result = result.replaceAll("GDBusProxy", "");
  result = result.replaceAll("GumScript", "");
  return result;
}

function hookLinker64() {
  // /system/bin/linker64
  const linker64 = Process.findModuleByName("linker64");
  if (!linker64) return;

  const symbols = linker64.enumerateSymbols();
  for (const symbol of symbols) {
    if (symbol.name.includes("call_constructors")) {

      console.log(`
[+] hook Native Function
- module: linker64
- function: call_constructors`);

      Interceptor.attach(symbol.address, {
        onEnter: function (args) {
          const soinfo = args[0];
          // const soNamePtr = soinfo.add(408).readPointer();
          // const soName = soNamePtr.readCString();
          const soName = soinfo.add(408).readPointer().readCString();

          if (!soName || soNameSet.has(soName)) return;
          soNameSet.add(soName);
          const isTarget = onlyHookTargetLibs ? targetLibs.has(soName) : true;
          if (!isTarget) return;
          const module = Process.findModuleByName(soName);
          if (!module) return;
          const base = module.base;
          const initProc = soinfo.add(184).readPointer();
          const initArray = soinfo.add(152).readPointer();
          const initArrayCount = soinfo.add(160).readU64() - 1;

          const initArrayFuncs = Array.from({ length: initArrayCount }, (_, index) =>
            initArray.add(8 * index).readPointer().sub(base)
          );

          console.log(`
[*] linker64 call_constructors onEnter
- so_name: ${soName}
- init_proc: ${(initProc == 0x0) ? "null" : initProc.sub(base)}
- init_array: ${(initArray == 0x0) ? "null" : initArray.sub(base)}
- init_array_count: ${initArrayCount}
  ${initArrayFuncs.join(', ')}`);

          if (soName in antiRoutines) {
            patchLib(soName, base);
          }
        }
      });
    }
  }
}

function hookLinker() {
  const linker = Process.findModuleByName("linker");
  if (!linker) return;

  const symbols = linker.enumerateSymbols();
  for (const symbol of symbols) {
    if (symbol.name.includes("call_constructors")) {

      console.log(`
[+] hook Native Function
- module: linker
- function: call_constructors`);

      Interceptor.attach(symbol.address, {
        onEnter: function (args) {
          const soinfo = args[0];
          // const soNamePtr = soinfo.add(376).readPointer();
          // const soName = soNamePtr.readCString();
          const soName = soinfo.add(376).readPointer().readCString();

          if (!soName || soNameSet.has(soName)) return;
          soNameSet.add(soName);
          const isTarget = onlyHookTargetLibs ? targetLibs.has(soName) : true;
          if (!isTarget) return;
          const module = Process.findModuleByName(soName);
          if (!module) return;
          const base = module.base;
          const initProc = soinfo.add(240).readPointer();
          const initArray = soinfo.add(224).readPointer();
          const initArrayCount = soinfo.add(228).readU32() - 1;

          const initArrayFuncs = Array.from({ length: initArrayCount }, (_, index) =>
            initArray.add(4 * index).readPointer().sub(base)
          );

          console.log(`
[*] linker call_constructors onEnter
- so_name: ${soName}
- init_proc: ${(initProc == 0x0) ? "null" : initProc.sub(base)}
- init_array: ${(initArray == 0x0) ? "null" : initArray.sub(base)}
- init_array_count: ${initArrayCount}
  ${initArrayFuncs.join(', ')}`);

          if (soName in antiRoutines) {
            patchLib(soName, base);
          }
        }
      });
    }
  }
}

// adb pull /system/lib64/libc.so
function regularBypass() {
  fgetsHook();
  strstrHook();
  // strcmpHook(); // 不稳定 容易崩 
  accessHook();
  connectHook();
  openHook();
}

function fgetsHook() {
  // hook fgets 函数
  const fgetsPtr = Module.findExportByName("libc.so", 'fgets');
  const fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
  Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
    const retval = fgets(buffer, size, fp);
    const bufstr = Memory.readCString(buffer);

    const result = replaceKeyword(bufstr);

    /*
    if (bufstr !== result) console.log(`
[*] fgets replace
- before: ${bufstr}
- after: ${result}`);
    */

    Memory.writeUtf8String(buffer, result);
    return retval;
  }, 'pointer', ['pointer', 'int', 'pointer']));
}

function strstrHook() {
  // hook strstr 函数
  const strstrPtr = Module.findExportByName("libc.so", 'strstr');
  Interceptor.attach(strstrPtr, {
    onEnter: function (args) {
      const pattern = args[1].readCString();
      // console.log(`!pattern: ${pattern}`);
      if (hasKeyword(pattern)) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(0);
    }
  });
}

function strcmpHook() {
  // hook strcmp 函数
  const strcmpPtr = Module.findExportByName("libc.so", 'strcmp');
  Interceptor.attach(strcmpPtr, {
    onEnter: function (args) {
      const str0 = args[0].readCString();
      const str1 = args[1].readCString();
      if (hasKeyword(str0) || hasKeyword(str1)) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(0);
    }
  });
}

function accessHook() {
  // hook access 函数
  const accessPtr = Module.findExportByName("libc.so", 'access');
  Interceptor.attach(accessPtr, {
    onEnter: function (args) {
      const path = args[0].readCString();
      if (
        path.includes("re.frida.server") ||
        path.includes("/data/local/tmp")
      ) {
        this.isCheck = true;
      }
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(-1); // 表示访问失败
    },
  });
}

function connectHook() {
  // hook connect 函数
  const connectPtr = Module.findExportByName("libc.so", 'connect');
  Interceptor.attach(connectPtr, {
    onEnter: function (args) {
      const portByte0 = args[1].add(2).readU8();
      const portByte1 = args[1].add(3).readU8();
      // 0x69A2 = 27042
      if (portByte0 === 0x69 && portByte1 === 0xA2) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(-1); // 表示连接失败
    },
  });
}

function openHook() {
  // hook open 函数
  const openPtr = Module.findExportByName("libc.so", 'open');
  Interceptor.attach(openPtr, {
    onEnter: function (args) {
      const filePath = args[0].readCString();
      if (filePath.startsWith("/proc/")) {
        if (filePath.endsWith("/maps") || filePath.endsWith("/stat")) {

          /*
          console.log(`
[*] libc open filePath replace
- before: ${filePath}
- after: ${tempFilePath}`);
          */

          if (autoGenMaps) {
            const bufstr = File.readAllText(filePath);
            File.writeAllText(tempFilePath, replaceKeyword(bufstr));
          }

          const filename = Memory.allocUtf8String(tempFilePath);
          args[0] = filename;
        }
      }
    },
  });
}

function hookPthreadCreate() {
  // hook pthread_create
  const pthreadCreatePtr = Module.findExportByName("libc.so", 'pthread_create');
  Interceptor.attach(pthreadCreatePtr, {
    onEnter: function (args) {
      const startRoutine = args[2];
      const module = Process.findModuleByAddress(startRoutine);

      if (targetLibs.has(module.name)) {
        const offset = startRoutine.sub(module.base);

        console.log(`
[*] libc pthread_create onEnter
- module: ${module.name}
- offset: ${offset}`);

      }
    }
  });
}

function hookLibdl() {
  /*
  const dlopenAddr = Module.findExportByName("libdl.so", "dlopen");
  Interceptor.attach(dlopenAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();

        if (path === "libc.so") {
          this.isTarget = true;
        }
      }
    },
    onLeave: function (_retval) {
      if (this.isTarget) {
        console.log(`
[*] libdl.so dlopen onEnter
- file: libc.so`);

        // hookPthreadCreate();
        // regularBypass(); // 一些通用绕过方法
      }
    }
  });
  */

  const androidDlopenExtAddr = Module.findExportByName("libdl.so", "android_dlopen_ext");
  Interceptor.attach(androidDlopenExtAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        this.filename = path.split('/').pop();

        // 分析前先打开
        console.log(`
[*] libdl.so android_dlopen_ext onEnter
- file: ${this.filename}
- path: ${path}`);


        if (targetLibs.has(this.filename)) {
          this.isTarget = true;

          /*
          在进入so文件之间 需要先hook linker
          以找到合适的时机进行hook 等init执行完后再patch就来不及了
          可以顺便获取init_proc和init_array的位置
          */
          hookLinker();
          hookLinker64();
        }
      }
    },
    onLeave: function () {
      if (this.isTarget) {
        const filename = this.filename;
        const jniOnload = Module.findExportByName(filename, "JNI_OnLoad");
        if (jniOnload) {
          Interceptor.attach(jniOnload, {
            onEnter: function (_args) {
              // 判断反调试是否在初始化时已经执行
              console.log(`
[*] ${filename} JNI_OnLoad onEnter`);
            },
            onLeave: function () {
              if (Java.available) {
                // Java.perform(doJavaHook);
              }
            },
          });
        }
      }
    },
  });

}

setImmediate(main);
