const packageName = "com.yimian.envcheck";
const targetLib = "libtestfrida.so";
// const fakeMapsPath = `/data/user/0/${packageName}/maps`;
const fakeMapsPath = `/data/data/${packageName}/maps`;
// 自动生成重定向maps文件
// 可能会导致频繁IO 最好手动生成
const autoGenMaps = true;

// 添加一些不需要hook的so
const soNameSet = new Set([
  "libandroid.so",
  "libbase.so",
  "libopenjdkjvmti.so",
  "libc.so",
  "libc++.so",
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
  "system@priv-app@RtMiCloudSDK@RtMiCloudSDK.apk@classes.dex",
  "android.hardware.graphics.mapper@4.0-impl-mediatek.so",
]);

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

function hookSoInit() {
  // /system/bin/linker64
  const linker64 = Process.findModuleByName("linker64");
  if (linker64) {
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

            if (soName && !soNameSet.has(soName)) {
              console.log(`[+] soName: ${soName}`);
              const module = Process.findModuleByName(soName);
              if (module) {
                const base = module.base;
                const initProc = soinfo.add(184).readPointer();
                const initArray = soinfo.add(152).readPointer();
                const initArrayCount = soinfo.add(160).readU64();

                const initArrayFuncs = Array.from({ length: initArrayCount }, (_, index) => {
                  const pointer = initArray.add(8 * index).readPointer();
                  if (pointer.toString() === "0x0") {
                    return null;
                  }
                  return pointer.sub(base);
                }).filter(item => item !== null);

                console.log(`
[*] linker64 call_constructors onEnter
- so_name: ${soName}
- init_proc: ${(initProc == 0x0) ? "null" : initProc.sub(base)}
- init_array: ${(initArray == 0x0) ? "null" : initArray.sub(base)}
- init_array_count: ${initArrayCount}
  ${initArrayFuncs.join(', ')}`);
              }
            }
          }
        });
      }
    }
  }

  const linker = Process.findModuleByName("linker");
  if (linker) {
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

            if (soName && !soNameSet.has(soName)) {
              soNameSet.add(soName);
              const module = Process.findModuleByName(soName);
              if (module) {
                const base = module.base;
                const initProc = soinfo.add(240).readPointer();
                const initArray = soinfo.add(224).readPointer();
                const initArrayCount = soinfo.add(228).readU32();

                const initArrayFuncs = Array.from({ length: initArrayCount }, (_, index) => {
                  const pointer = initArray.add(4 * index).readPointer();
                  if (pointer.toString() === "0x0") {
                    return null;
                  }
                  return pointer.sub(base);
                }).filter(item => item !== null);

                console.log(`
[*] linker call_constructors onEnter
- so_name: ${soName}
- init_proc: ${(initProc == 0x0) ? "null" : initProc.sub(base)}
- init_array: ${(initArray == 0x0) ? "null" : initArray.sub(base)}
- init_array_count: ${initArrayCount}
  ${initArrayFuncs.join(', ')}`);
              }
            }
          }
        });
      }
    }
  }
}

// adb pull /system/lib64/libc.so
function regularBypass() {
  // hook fgets 函数
  const fgetsPtr = Module.findExportByName("libc.so", 'fgets');
  const fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
  Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
    const retval = fgets(buffer, size, fp);
    const bufstr = Memory.readCString(buffer);

    const result = replaceKeyword(bufstr);

    if (bufstr !== result) console.log(`
[*] fgets replace
- before: ${bufstr}
- after: ${result}`);

    Memory.writeUtf8String(buffer, result);
    return retval;
  }, 'pointer', ['pointer', 'int', 'pointer']));

  // hook strstr 函数
  const strstrPtr = Module.findExportByName("libc.so", 'strstr');
  Interceptor.attach(strstrPtr, {
    onEnter: function (args) {
      const pattern = args[1].readCString();
      if (hasKeyword(pattern)) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(0);
    }
  });

  // hook strcmp 函数
  // 不稳定 容易崩
  /*
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
  */

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

  // hook open 函数
  const openPtr = Module.findExportByName("libc.so", 'open');
  Interceptor.attach(openPtr, {
    onEnter: function (args) {
      const filePath = args[0].readCString();
      if (filePath.includes("/proc/") && filePath.includes("/maps")) {
        console.log(`
[*] libc open filePath replace
- before: ${filePath}
- after: ${fakeMapsPath}`);

        if (autoGenMaps) {
          const bufstr = File.readAllText(filePath);
          File.writeAllText(fakeMapsPath, replaceKeyword(bufstr));
        }

        const filename = Memory.allocUtf8String(fakeMapsPath);
        args[0] = filename;
      }
    },
  });
}


function main() {

  hookSoInit();
  regularBypass();

  const dlopenAddr = Module.findExportByName("libdl.so", "android_dlopen_ext");
  Interceptor.attach(dlopenAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        // 分析前先打开
        console.log(`
[*] libdl.so android_dlopen_ext onEnter
- path: ${path}`);
        if (path.includes(targetLib)) {
          this.isTarget = true;
        }
      }
    },
    onLeave: function () {
      if (this.isTarget) {
        const jniOnload = Module.findExportByName(targetLib, "JNI_OnLoad");
        console.log("[hit JNI_OnLoad]: " + jniOnload);
        // 如果有输出的话 说明检测点在JNI_OnLoad之中或者之后
        // 否则可能在.init_proc .init_array .init_xxx等函数中
        Interceptor.attach(jniOnload, {
          onEnter: function (_args) {
            // 其中有检测是否有java层hook
            // hook后 & 0x80000 != 0
            console.log("[func invoke]: JNI_OnLoad");
          },
          onLeave: function () {
            if (Java.available) {
              // Java.perform(doJavaHook);
            }
          },
        });
      }
    },
  });
}

setImmediate(main);
