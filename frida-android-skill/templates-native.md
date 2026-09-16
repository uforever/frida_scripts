# Native 层模板

所有代码可直接运行（Frida 17 API）。

## 1. so 加载时机 hook：android_dlopen_ext + JNI_OnLoad

native 逆向的起点。目标 so 尚未加载时，必须等它加载完再取模块与符号。日志能区分检测点位置：`JNI_OnLoad` 有输出说明检测在其中或之后；无输出则在 `.init_proc` / `.init_array`：

```javascript
const targetLib = "libmsaoaidsec.so";

function main() {
  const libdl = Process.getModuleByName("libdl.so");
  const adeAddr = libdl.getExportByName("android_dlopen_ext");
  Interceptor.attach(adeAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        console.log("[dylib open]: ", path);
        if (path.includes(targetLib)) {
          this.isTarget = true;
        }
      }
    },
    onLeave: function () {
      if (this.isTarget) {
        // 目标 so 可能没有导出 JNI_OnLoad，用 find 保持脚本存活
        const jniOnload = Process.getModuleByName(targetLib).findExportByName("JNI_OnLoad");
        console.log("[hit JNI_OnLoad]: " + jniOnload);
        if (jniOnload) {
          Interceptor.attach(jniOnload, {
            onEnter: function (_args) { console.log("[func invoke]: JNI_OnLoad"); },
            onLeave: function () {
              if (Java.available) Java.perform(doJavaHook);
            },
          });
        }
      }
    },
  });
}

function doJavaHook() {
  // 业务 Java hook 写在这里
}

setImmediate(main);
```

同时监控 `dlopen` 与 `android_dlopen_ext` 时，复用同一个 libdl 模块对象：

```javascript
const libdl = Process.getModuleByName("libdl.so");
const dlopenAddr = libdl.getExportByName("dlopen");
const adeAddr = libdl.getExportByName("android_dlopen_ext");
```

## 2. linker 构造阶段 hook：call_constructors

需要在 init 阶段（早于 JNI_OnLoad）介入时使用。通过 soinfo 结构读取 so 名、init_proc、init_array（**偏移与 Android 版本相关**：linker64 上 so_name≈+408、init_proc≈+184、init_array≈+152、count≈+160；linker（32位）上 so_name≈+376、init_proc≈+240、init_array≈+224、count≈+228，使用前需按目标版本校准）：

```javascript
const soNameSet = new Set([
  "libandroid.so", "libc.so", "libc++.so", "libcutils.so", "libdl.so",
  "liblog.so", "libutils.so", "libm.so", "libEGL.so",   // 按需增删
]);

function hookSoInit() {
  const linker = (Process.pointerSize == 8) ?
    Process.findModuleByName("linker64") : Process.findModuleByName("linker");
  if (linker) {
    const symbols = linker.enumerateSymbols();
    // void soinfo::call_constructors()
    for (const symbol of symbols) {
      if (symbol.name.includes("call_constructors")) {
        Interceptor.attach(symbol.address, {
          onEnter: function (args) {
            const soinfo = args[0];
            const soName = soinfo.add(408).readPointer().readCString();
            if (!soNameSet.has(soName)) {
              soNameSet.add(soName);
              const module = Process.findModuleByName(soName);
              if (module) {
                const base = module.base;
                const initProc = soinfo.add(184).readPointer();
                const initArray = soinfo.add(152).readPointer();
                const initArrayCount = soinfo.add(160).readU64();

                const initArrayFuncs = Array.from({ length: initArrayCount }, (_, index) =>
                  initArray.add(Process.pointerSize * index).readPointer().sub(base)
                );

                console.log(`
[*] call_constructors onEnter
- so_name: ${soName}
- init_proc: ${(initProc == 0x0) ? "null" : initProc.sub(base)}
- init_array: ${(initArray == 0x0) ? "null" : initArray.sub(base)}
- init_array_count: ${initArrayCount}
  ${initArrayFuncs.join(', ')}`);
              }
            }
          }
        });
        break;
      }
    }
  }
}

setImmediate(hookSoInit);
```

在构造阶段对已加载目标 so 做处理（nop 检测函数等）的完整用法见 `anti-detection.md`。

## 3. JNI 动态注册监控

Java 方法被 `RegisterNatives` 动态注册时取证（方法签名、so 与偏移）。`StdString` 用于读取 libart 返回的 `std::string`。用 spawn 模式，尽量早于业务 so 注册：

```javascript
const PKG_NAME = "com.example.demo"; // 需要修改这里

const STD_STRING_SIZE = 3 * Process.pointerSize;
class StdString {
  constructor() {
    this.handle = Memory.alloc(STD_STRING_SIZE);
  }

  dispose() {
    const [data, isTiny] = this._getData();
    if (!isTiny) {
      Java.api.$delete(data);
    }
  }

  disposeToString() {
    const result = this.toString();
    this.dispose();
    return result;
  }

  toString() {
    const [data] = this._getData();
    return data.readUtf8String();
  }

  _getData() {
    const str = this.handle;
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
    return [data, isTiny];
  }
}

function prettyMethod(method_id, withSignature) {
  const result = new StdString();
  Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
  return result.disposeToString();
}

function main() {
  const libart = Process.getModuleByName("libart.so").enumerateExports();

  for (const export_func of libart) {
    if (export_func.name.includes("RegisterNativeMethod")) {
      Interceptor.attach(export_func.address, {
        onEnter: function (args) {
          const methodName = prettyMethod(args[1], true);
          const retvalType = methodName.split(' ')[0];
          if (methodName.includes(PKG_NAME)) {
            const module = Process.findModuleByAddress(args[2]);
            const offset = args[2].sub(module.base);
            console.log(`
[!] RegisterNativeMethod
- method: ${methodName}
- module: ${module.name}
- offset: ${offset}`);
            // 顺便观测 native 方法本身的输入输出
            Interceptor.attach(args[2], {
              onLeave: function (retval) {
                if (retvalType === 'int') {
                  console.log(`[*] Leave NativeMethod ${methodName}\n- retval: ${retval}`);
                } else if (retvalType === 'java.lang.String') {
                  console.log(`[*] Leave NativeMethod ${methodName}\n- retval: ${Java.cast(retval, Java.use('java.lang.String'))}`);
                }
              },
            });
          }
        },
      });
    }
  }
}

setImmediate(main);
```

## 4. 返回值修改

```javascript
const targetLib = "libdemo.so";

function HookNative() {
  const libdl = Process.getModuleByName("libdl.so");
  const adeAddr = libdl.getExportByName("android_dlopen_ext");
  Interceptor.attach(adeAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      this.isTarget = false;
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        if (path.includes(targetLib)) this.isTarget = true;
      }
    },
    onLeave: function () {
      if (this.isTarget) {
        const funcAddr = Process.getModuleByName(targetLib).findExportByName("Java_com_example_demo_MainActivity_stringFromJNI");
        // 返回值篡改：替换为自定义 Java 字符串
        Interceptor.attach(funcAddr, {
          onLeave: function (retVal) {
            retVal.replace(Java.vm.tryGetEnv().newStringUtf("Foo Bar"));
          },
        });
      }
    }
  });
}

setImmediate(HookNative);
```

## 5. 参数篡改后调用原函数

```javascript
// 在 NativeCallback 中先打印/修改参数，再调用原函数
const oldFunc = new NativeFunction(funcAddr, 'int', ['pointer', 'pointer', 'pointer']);
const newFunc = new NativeCallback(function (env, thiz, str) {
  console.log("[key argument]: ", Java.vm.tryGetEnv().getStringUtfChars(str, null).readCString());
  const newInput = Java.vm.tryGetEnv().newStringUtf("空山新雨后");
  const newRetVal = oldFunc(env, thiz, newInput);
  return newRetVal;
}, 'int', ['pointer', 'pointer', 'pointer']);
Interceptor.replace(oldFunc, newFunc);
```

onEnter 中直接改参数（不替换函数）：

```javascript
Interceptor.attach(module.base.add(0x1596), {
    onEnter: function (args) {
        const outputPath = args[0].add(5);
        args[0] = args[1];        // 交换第 1、2 个参数
        args[1] = outputPath;
        console.log('Argument 1: ' + args[0].readUtf8String());
        console.log('Argument 2: ' + args[1].readUtf8String());
    },
});
```

## 6. native 函数主动调用

根据基址 + offset 主动调用（未导出函数）。注意 thumb 模式地址 +1，arm64 直接用偏移：

```javascript
const targetLib = "libCheckRegister.so";

function sub_1498(arg1, arg2) {
  const baseAddress = Process.getModuleByName(targetLib).base;
  const offset = 0x1498;
  const targetFuncAddr = baseAddress.add(offset + 1);   // 使用.add方法 不能直接加
  const targetFunc = new NativeFunction(targetFuncAddr, 'int', ['pointer', 'pointer']);
  return targetFunc(arg1, arg2);
}

function HookNative() {
  // 用 Memory.alloc 准备参数缓冲区
  const arg1Output = Memory.alloc(100);
  const arg2Passwd = Memory.alloc(100);
  arg2Passwd.writeUtf8String("MzMz");

  console.log("before sub_1498 output: " + arg1Output.readUtf8String());
  const retval = sub_1498(arg1Output, arg2Passwd);
  console.log("sub_1498 retval: " + retval);
  console.log("after sub_1498 output: " + arg1Output.readUtf8String());
}

// 未导出函数要等 so 加载后才能调用，最好设置延迟
setTimeout(HookNative, 3000);
```

## 7. 内存读写

基址 + offset 的链式读取，先判断值还是指针：

```javascript
const targetLib = "libcrackme.so";

function main() {
    const baseAddr = Process.getModuleByName(targetLib).base;
    const off_628C = baseAddr.add(0x628C);

    // 看看这个地址是值还是指针
    console.log(off_628C.readCString());
    console.log(off_628C.readPointer());

    // 是指针则再解引用
    console.log(off_628C.readPointer().readCString());
}

setImmediate(main);
```

## 8. hook clone 获取线程入口

`pthread_create` 内部调用 `clone`，线程函数地址存在子线程结构体 +96 偏移处（读取第 4 个参数 + 96）。**有些库的实现绕过 `pthread_create`，直接通过 `clone` 手动创建线程**，因此 hook `clone` 是比 hook `pthread_create` 更高级的定位方式，两种线程创建都能观测到。反检测场景中先用本脚本确定检测线程的 `module + offset`，再 nop 这些线程入口（工作流见 `anti-detection.md` §6）：

```javascript
function hookClone() {
  const libc = Process.getModuleByName('libc.so');
  const cloneFunc = libc.findExportByName("clone");
  if (!cloneFunc) {
    console.log("clone function not found");
    return;
  }
  Interceptor.attach(cloneFunc, {
    onEnter(args) {
      if (args[3] != 0) {
        const startRoutine = args[3].add(96).readPointer();
        const module = Process.findModuleByAddress(startRoutine);
        if (module) {
          const offset = startRoutine.sub(module.base);
          console.log(`Thread start routine found: ${module.name} + 0x${offset.toString(16)}`);
        }
      }
    }
  });
}

setImmediate(hookClone);
```

## 9. patchCode 与 Arm64Writer

两种 nop 线程检测函数的方式。`Memory.patchCode` 会处理代码页权限：

```javascript
// 方式一：将调用 pthread_create 的指令 nop 掉（对抗 hook 特征检测）
// .text:0000000000010984  4B F7 FF 97   BL .pthread_create
const newThreadFunc = baseAddr.add(0x10984);
Memory.patchCode(newThreadFunc, 0x4, function (code) {
    const codeWriter = new Arm64Writer(code, { pc: newThreadFunc });
    codeWriter.putNop();
    codeWriter.flush();
});

// 方式二：把线程函数入口直接改成 ret
function nopFunc(parg2) {
  Memory.protect(parg2, 4, 'rwx');   // 修改该地址的权限为可读可写
  const writer = new Arm64Writer(parg2);
  writer.putRet();                   // 直接 ret 不返回值
  writer.flush();
  writer.dispose();
}

// 方式三：Interceptor.replace 成空回调（可打印日志确认触发）
function nop(base, offset) {
  Interceptor.replace(base.add(offset), new NativeCallback(function () {
    console.log(`thread func sub_${offset.toString(16).toUpperCase()} noped`)
  }, 'void', []));
}
```

arm64 定向 patch（来自逆向证据的返回值 patch，见 `anti-detection.md` §7）：

```javascript
function patchReturnZero(target) {
  Memory.patchCode(target, 8, function (code) {
    code.writeU32(0x52800000);        // mov w0, #0
    code.add(4).writeU32(0xd65f03c0); // ret
  });
}
function patchReturnOnly(target) {
  Memory.patchCode(target, 4, function (code) {
    code.writeU32(0xd65f03c0);        // ret
  });
}
```

## 10. Stalker 指令跟踪

跟踪主模块指令流：反汇编 + 字节码 + 寄存器上下文。开销极大，只跟踪主模块范围并设置停止条件：

```javascript
const mainModule = Process.mainModule;
const appStart = mainModule.base;
const appEnd = appStart.add(mainModule.size);
const x64 = Process.pointerSize == 8;

function formattedAddress(address) {
  const l = x64 ? 16 : 8;
  return `${address}`.substring(2).padStart(l, '0');
}

const mainThread = Process.enumerateThreads()[0];
Stalker.follow(mainThread.id, {
  transform(iterator) {
    let instruction = iterator.next();

    const startAddress = instruction.address;
    const isAppCode = startAddress.compare(appStart) >= 0 &&
      startAddress.compare(appEnd) === -1;
    const canEmitNoisyCode = iterator.memoryAccess === 'open';

    do {
      if (isAppCode && canEmitNoisyCode) {
        const insAddress = instruction.address;
        const byteArray = insAddress.readByteArray(instruction.size);
        const uint8Array = new Uint8Array(byteArray);
        const byteCode = Array.from(uint8Array).map(byte => ('0' + byte.toString(16)).slice(-2)).join(' ').padEnd(44, ' ');
        const disassemble = `${instruction.mnemonic} ${instruction.opStr}`.padEnd(50, ' ');

        const onMatch = (context) => {
          const registers = x64
            ? ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
            : ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
          const regStr = registers.map(r => `${r}: ${formattedAddress(context[r])}`).join(' ');
          console.log(`${insAddress} | ${byteCode} | ${disassemble} | ${regStr}`);
        };
        iterator.putCallout(onMatch);
      }
      iterator.keep();
    } while ((instruction = iterator.next()) !== null);
  },
});
// 停止：Stalker.unfollow(mainThread.id); Stalker.garbageCollect();
```

按调用频率定位热点函数（配合反检测分析）：

```javascript
function traceSecurityThread(threadId) {
    Stalker.follow(threadId, {
        events: { call: true, ret: false, exec: false },
        onCallSummary(summary) {
            Object.keys(summary).forEach(function(addr) {
                var mod = Process.findModuleByAddress(ptr(addr));
                if (mod && mod.name === 'libmsaoaidsec.so') {
                    console.log('detect call +0x' + ptr(addr).sub(mod.base).toString(16) + ' x' + summary[addr]);
                }
            });
        }
    });
}
```

## 11. so 内函数定位与替换（主模块 offset）

主模块内按 offset 定位函数，attach 观测、replace 直接对调两个函数、NativeFunction 主动调用：

```javascript
function main() {
    const module = Process.mainModule;

    const xxteaEncrypt = module.base.add(0x12F5);
    const xxteaDecrypt = module.base.add(0x1456);

    Interceptor.attach(xxteaDecrypt, {
        onEnter: function (_args) { console.log("xxtea_decrypt called"); },
    });

    // 用 NativeFunction 包装后，可直接把加密函数替换为解密函数
    const xxtea_encrypt = new NativeFunction(xxteaEncrypt, 'int', ['pointer', 'int', 'int']);
    const xxtea_decrypt = new NativeFunction(xxteaDecrypt, 'int', ['pointer', 'int', 'int']);
    Interceptor.replace(xxtea_encrypt, xxtea_decrypt);
}

setImmediate(main);
```

## 12. 未导出符号定位：枚举 symbols

非导出函数从 `enumerateSymbols()` 找（导出函数用 `enumerateExports()`）。so 未加载时配合延迟：

```javascript
const targetLib = "libroysue.so";

function HookNative() {
    const symbols = Process.getModuleByName(targetLib).enumerateSymbols();
    for (const iterator of symbols) {
        if (iterator.name === "ll11lll1l1") {
            Interceptor.attach(iterator.address, {
                onLeave: function (result) {
                    console.log('key: ', result.readCString());
                },
            });
        }
        if (iterator.name === "ll11l1l1l1") {
            Interceptor.attach(iterator.address, {
                onLeave: function (result) {
                    console.log('iv: ', result.readUtf8String());
                },
            });
        }
    }
}

// 这里最好设置延迟 否则可能加载不到
setTimeout(HookNative, 3000);
```

## 13. SSL 明文抓取（native 侧）

用 `ApiResolver` 模糊定位 libssl 的 `SSL_read`/`SSL_write`，输出明文（Java 层 Socket/TCP/UDP 见 `network-tls.md` §4）：

```javascript
const useHexDump = false;

function doNativeHook() {
  const resolver = new ApiResolver("module");

  const nativeBufOpFunc = function (buffer, length) {
    let result = "\n";
    if (length > 0) {
      if (useHexDump) {
        result += hexdump(buffer, { offset: 0, length: length, header: true, ansi: true });
      } else {
        result += buffer.readCString(length);   // readUtf8String 可能因非法字节报错
      }
    }
    return result;
  };

  const sslModuleName = "*libssl*";   // iOS 上用 "*libboringssl*"
  const sslApiList = ["SSL_read", "SSL_write"];
  const sslApiAddress = {};
  for (const sslApi of sslApiList) {
    const matches = resolver.enumerateMatchesSync(`exports:${sslModuleName}!${sslApi}`);
    if (matches.length == 0) { console.log(`[!] No matches for ${sslApi}`); continue; }
    if (matches.length > 1) { console.log(`[!] Multiple matches for ${sslApi}`); continue; }
    sslApiAddress[sslApi] = matches[0].address;
  }

  // int SSL_write(SSL *ssl, void *buf, int num);
  Interceptor.attach(sslApiAddress["SSL_write"], {
    onEnter: function (args) { this.buffer = args[1]; this.length = args[2].toUInt32(); },
    onLeave: function (retval) {
      retval |= 0;
      if (retval > 0) console.log(`\n[*] SSL_write\n- buffer: ${nativeBufOpFunc(this.buffer, retval)}`);
    },
  });

  // int SSL_read(SSL *ssl, void *buf, int num);
  Interceptor.attach(sslApiAddress["SSL_read"], {
    onEnter: function (args) { this.buffer = args[1]; this.length = args[2].toUInt32(); },
    onLeave: function (retval) {
      retval |= 0;
      if (retval > 0) console.log(`\n[*] SSL_read\n- buffer: ${nativeBufOpFunc(this.buffer, retval)}`);
    },
  });
}

doNativeHook();
```
