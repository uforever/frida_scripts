# 反检测：方法论与绕过模板

安卓应用的 Frida 检测识别与绕过。核心约定：

1. **先分析后绕过** — 不要盲目堆砌反检测代码，先用探针定位检测来源
2. 反检测 hook 必须在 `Java.perform()` 之前安装（脚本加载时立即执行）
3. **安全 SDK 可能加密关键字符串** — `pthread_create`、`dlsym` 等字符串可能运行时 XOR 解密后传给 dlsym
4. **区分直接导入和动态解析** — 用 `llvm-readelf --dyn-syms <so> | grep pthread` 检查 SO 是否直接导入 `pthread_create`，没有则必须通过 dlsym 拦截
5. 脚本执行顺序：先 dlopen 阻断 → EGL 崩溃拦截（模拟器必须）→ 其余反检测 hook → 最后 Java 层 hook

## 1. 四步定位法

**第一步：探针脚本定位检测来源。** hook 线程创建与所有退出方式，打印调用栈：

```javascript
'use strict';
var libc = Process.getModuleByName('libc.so');

// 1. 监控pthread_create — 找到检测线程的来源模块和偏移
Interceptor.attach(libc.getExportByName('pthread_create'), {
	onEnter(args) {
		var fn = args[2];
		var mod = Process.findModuleByAddress(fn);
		if (mod === null || mod.name === 'libart.so') return;
		console.log('thread: ' + mod.name + ' +0x' + fn.sub(mod.base).toString(16));
	}
});

// 2. 监控所有退出方式 — 找到谁杀了进程
['exit', '_exit', 'exit_group'].forEach(function(name) {
	var addr = libc.findExportByName(name);
	if (addr === null) return;
	Interceptor.attach(addr, {
		onEnter(args) {
			console.log('=== ' + name + '(' + args[0] + ') ===');
			console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
				.map(DebugSymbol.fromAddress).join('\n'));
		}
	});
});

// 3. 监控kill/tgkill — 捕获signal方式的自杀
Interceptor.attach(libc.getExportByName('kill'), {
	onEnter(args) {
		var pid = args[0].toInt32();
		var sig = args[1].toInt32();
		if (pid === Process.id || pid === 0) {
			console.log('=== kill(self, sig=' + sig + ') ===');
			console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
				.map(DebugSymbol.fromAddress).join('\n'));
		}
	}
});

// 4. 监控abort — EGL崩溃和检测触发的abort
Interceptor.attach(libc.getExportByName('abort'), {
	onEnter() {
		console.log('=== abort() ===');
		console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
			.map(DebugSymbol.fromAddress).join('\n'));
	}
});

// 5. 监控raise — signal handler内部路径
var raiseAddr = libc.findExportByName('raise');
if (raiseAddr !== null) {
	Interceptor.attach(raiseAddr, {
		onEnter(args) {
			console.log('=== raise(sig=' + args[0].toInt32() + ') ===');
			console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
				.map(DebugSymbol.fromAddress).join('\n'));
		}
	});
}

// 6. 监控clone — 部分库绕过pthread_create，直接通过clone手动创建线程
// pthread_create内部最终也调用clone，线程函数地址存在子线程结构体+96偏移处
// （读取第4个参数+96），比hook pthread_create更底层，两种线程创建方式都能观测到
var cloneAddr = libc.findExportByName('clone');
if (cloneAddr !== null) {
	Interceptor.attach(cloneAddr, {
		onEnter(args) {
			if (args[3] != 0) {
				var startRoutine = args[3].add(96).readPointer();
				var mod = Process.findModuleByAddress(startRoutine);
				if (mod !== null && mod.name !== 'libart.so') {
					console.log('clone thread: ' + mod.name + ' +0x' + startRoutine.sub(mod.base).toString(16));
				}
			}
		}
	});
}

console.log('probe installed');
```

**第二步：分析探针输出。**

| 观察点 | 含义 | 处理 |
|--------|------|------|
| `thread: libmsaoaidsec.so +0x1c544` | 安全SDK创建了检测线程 | 阻断SO加载或nop该入口 |
| `clone thread: libxxx.so +0x1234` | 检测线程绕过pthread_create，直接通过clone创建 | 按检测线程处理，nop该offset |
| `_exit(0)` from libmsaoaidsec.so | 检测到frida后调用_exit退出 | 确认检测来源后定点处理 |
| `abort()` from libhwui.so | 模拟器EGL渲染崩溃，非检测 | 见 §9 单独处理 |
| 无任何exit/abort/kill但进程死了 | inline svc 或内核级SIGSEGV | 见 §5，普通hook无效 |

进程死法识别：`logcat | grep ApplicationExitInfo` 中 `reason=2 (SIGNALED) status=9 description=exit_self_<pid>_<uid>` 表示进程通过 SIGKILL 自杀（`exit_self_*` 是自杀的明确标志，与系统 kill 区分）。

**第三步：针对性编写绕过**（§2-§7 按检测手段选择）。
**第四步：验证**：检测线程不再创建、无异常 exit/abort/kill、进程存活功能正常、Frida 会话保持存活。

## 2. so 加载阻断（快速验证）

hook `dlopen`/`android_dlopen_ext`，把检测 SO 路径替换为空串。仅用于验证"不加载安全库时 App 能否启动"，不是长期方案：

```javascript
function hookDlopenExt() {
	var blockedLibs = ['libmsaoaidsec.so'];

	function isBlocked(path) {
		if (path === null) return false;
		for (var i = 0; i < blockedLibs.length; i++) {
			if (path.indexOf(blockedLibs[i]) !== -1) return true;
		}
		return false;
	}

	function attachDlopen(name) {
		var addr = Module.findGlobalExportByName(name);
		if (addr === null) {
			console.log('anti-detect: ' + name + ' not found, skip');
			return;
		}
		Interceptor.attach(addr, {
			onEnter(args) {
				this.blocked = false;
				var pathptr = args[0];
				if (pathptr === undefined || pathptr === null || pathptr.isNull()) return;
				var soPath = pathptr.readCString();
				if (isBlocked(soPath)) {
					console.log('anti-detect: block ' + name + ' ' + soPath);
					args[0] = Memory.allocUtf8String('');
					this.blocked = true;
				}
			},
			onLeave(retval) {
				if (this.blocked) {
					console.log('anti-detect: ' + name + ' blocked, retval=' + retval);
				}
			}
		});
		console.log('anti-detect: hooked ' + name);
	}

	attachDlopen('dlopen');
	attachDlopen('android_dlopen_ext');
}
```

动态加载观测探针（记录全部加载路径，判断时机）：

```javascript
function probeDlopen(){
	var addr = Module.findGlobalExportByName('android_dlopen_ext') || Module.findGlobalExportByName('dlopen');
	if (addr === null) return;
	Interceptor.attach(addr, {
		onEnter: function(args){
			var pathPtr = args[0];
			if (pathPtr === undefined || pathPtr === null || pathPtr.isNull()) return;
			var path = pathPtr.readCString();
			if (path === null) return;
			console.log('dlopen path=' + path);
		}
	});
}
```

常见安全 SDK so 黑名单：

| 厂商 | SO名称 |
| --- | --- |
| **奇虎360** | `libjiagu.so`, `libprotectClass.so`, `libjiagu_art.so`, `libjiagu_x64.so`, `libjiagu_ls.so` |
| **腾讯** (乐固 / 御安全) | `libshell-super.so`, `libBugly-yaq.so`, `libtosprotection.so`, `libtup.so` |
| **爱加密** | `libexec.so`, `libexecmain.so`, `ijiami.dat` |
| **梆梆安全** | `libsecexe.so`, `libsecmain.so`, `libDexHelper.so` |
| **娜迦信息** | `libchaosvmp.so`, `libddog.so`, `libfdog.so`, `libedog.so` |
| **网易** (易盾) | `libnesec.so` |
| **顶象科技** | `libx3g.so` |
| **几维安全** | `libkwscmm.so`, `libkwscr.so`, `libkwslinker.so` |
| **通付盾** | `libegis.so`, `libNSaferOnly.so` |
| **阿里巴巴** (聚安全 / 无线保镖) | `libsgmain.so`, `libsgsecuritybody.so`, `libmobisec.so`, `libdemolish.so` |
| **移动安全联盟 (MSA)** | `libmsaoaidsec.so` |

## 3. libc 层通用绕过（fgets / strstr / access / connect / open）

对读取 `/proc/self/status`、内存字符串搜索、文件访问、端口扫描的常规检测（轻度对抗足够）：

```javascript
function hasKeyword(str) {
  return str.includes("frida") || str.includes(":69A2") || str.includes("gum-js") ||
    str.includes("REJECT") || str.includes("gmain") || str.includes("gdbus") ||
    str.includes("linjector") || str.includes("agent") || str.includes("/data/local/tmp") ||
    str.includes("GLib-GIO") || str.includes("GumScript") || str.includes("adb");
}

function replaceKeyword(str) {
  let result = str.replace(/TracerPid:\t\d+/g, "TracerPid:\t0");
  ["frida", "gum-js", "REJECT", "gmain", "gdbus", "linjector", "GLib-GIO", "GumScript"].forEach(
    kw => result = result.replaceAll(kw, ""));
  result = result.replaceAll("agent", "bar");
  result = result.replaceAll("/data/local/tmp", "/");
  return result;
}

// 1. fgets：/proc/self/status 的 TracerPid 读取（fopen+fgets 方式）
function fgetsHook() {
  const fgetsPtr = Process.getModuleByName("libc.so").getExportByName('fgets');
  const fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
  Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
    const retval = fgets(buffer, size, fp);
    const bufstr = buffer.readCString();
    const result = replaceKeyword(bufstr);
    buffer.writeUtf8String(result);
    return retval;
  }, 'pointer', ['pointer', 'int', 'pointer']));
}

// 2. strstr：内存特征字符串搜索
function strstrHook() {
  const strstrPtr = Process.getModuleByName("libc.so").getExportByName('strstr');
  Interceptor.attach(strstrPtr, {
    onEnter: function (args) {
      const pattern = args[1].readCString();
      if (hasKeyword(pattern)) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(0);
    }
  });
}

// 3. strcmp：字符串比较类检测（不稳定容易崩，按需启用）
function strcmpHook() {
  const strcmpPtr = Process.getModuleByName("libc.so").getExportByName('strcmp');
  Interceptor.attach(strcmpPtr, {
    onEnter: function (args) {
      if (hasKeyword(args[0].readCString()) || hasKeyword(args[1].readCString())) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(0);
    }
  });
}

// 4. access：文件存在性检测
function accessHook() {
  const accessPtr = Process.getModuleByName("libc.so").getExportByName('access');
  Interceptor.attach(accessPtr, {
    onEnter: function (args) {
      const path = args[0].readCString();
      if (path.includes("re.frida.server") || path.includes("/data/local/tmp")) {
        this.isCheck = true;
      }
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(-1); // 表示访问失败
    },
  });
}

// 5. connect：端口连接检测（0x69A2 = 27042）
function connectHook() {
  const connectPtr = Process.getModuleByName("libc.so").getExportByName('connect');
  Interceptor.attach(connectPtr, {
    onEnter: function (args) {
      const portByte0 = args[1].add(2).readU8();
      const portByte1 = args[1].add(3).readU8();
      if (portByte0 === 0x69 && portByte1 === 0xA2) this.isCheck = true;
    },
    onLeave: function (retval) {
      if (this.isCheck) retval.replace(-1);
    },
  });
}

// 6. open：/proc/<pid>/maps|stat 读取重定向到过滤后的临时文件
// tempFilePath 为预生成的干净 maps 文件；autoGenMaps 时用 File 读写实时生成
const tempFilePath = `/data/data/<package>/tempfile`;
const autoGenMaps = true;

function openHook() {
  const openPtr = Process.getModuleByName("libc.so").getExportByName('open');
  Interceptor.attach(openPtr, {
    onEnter: function (args) {
      const filePath = args[0].readCString();
      if (filePath.startsWith("/proc/")) {
        if (filePath.endsWith("/maps") || filePath.endsWith("/stat")) {
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
```

Android 上 `/proc` 主要走 `openat` 而非 `open`；不用临时文件、需要管道返回过滤内容的高级写法见本章 §4 的 `hookProcMaps`。

## 4. /proc/self/maps 扫描检测（openat + pipe 过滤）

检测原理：读 `/proc/self/maps` 查找 `frida-agent` 等映射。绕过：hook `openat`，对 maps 返回装了过滤内容的管道 fd：

```javascript
function hookProcMaps() {
	var libc = Process.getModuleByName('libc.so');
	var openFn = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int']);
	var readFn = new NativeFunction(libc.getExportByName('read'), 'int', ['int', 'pointer', 'int']);
	var closeFn = new NativeFunction(libc.getExportByName('close'), 'int', ['int']);
	var pipeFn = new NativeFunction(libc.getExportByName('pipe'), 'int', ['pointer']);
	var writeFn = new NativeFunction(libc.getExportByName('write'), 'int', ['int', 'pointer', 'int']);
	var fridaKeywords = ['frida', 'gmain', 'gdbus', 'gum-js-loop', 'linjector'];

	function readAndFilter(path) {
		var fd = openFn(Memory.allocUtf8String(path), 0);
		if (fd === -1) return null;
		var chunks = [];
		var buf = Memory.alloc(0x4000);
		var n;
		while ((n = readFn(fd, buf, 0x3fff)) > 0) {
			chunks.push(buf.readCString());
		}
		closeFn(fd);
		var lines = chunks.join('').split('\n');
		var filtered = [];
		for (var i = 0; i < lines.length; i++) {
			var dominated = false;
			var lower = lines[i].toLowerCase();
			for (var k = 0; k < fridaKeywords.length; k++) {
				if (lower.indexOf(fridaKeywords[k]) !== -1) { dominated = true; break; }
			}
			if (!dominated) filtered.push(lines[i]);
		}
		return filtered.join('\n');
	}

	function createFakeFd(content) {
		var fds = Memory.alloc(8);
		if (pipeFn(fds) !== 0) return -1;
		var readEnd = fds.readS32();
		var writeEnd = fds.add(4).readS32();
		var buf = Memory.allocUtf8String(content);
		writeFn(writeEnd, buf, content.length);
		closeFn(writeEnd);
		return readEnd;
	}

	var openatAddr = libc.getExportByName('openat');
	Interceptor.attach(openatAddr, {
		onEnter(args) {
			this.redirect = false;
			var p = args[1];
			if (p === undefined || p === null || p.isNull()) return;
			var path = p.readCString();
			if (path !== null && path.match(/\/proc\/(\d+|self)\/maps$/)) {
				this.redirect = true;
			}
		},
		onLeave(retval) {
			if (!this.redirect) return;
			var origFd = retval.toInt32();
			if (origFd < 0) return;
			var content = readAndFilter('/proc/self/maps');
			closeFn(origFd);
			if (content !== null) {
				retval.replace(createFakeFd(content));
			}
		}
	});
}
```

`/proc/net/tcp` 端口扫描同理：端口 27042 → hex `69A2`（9229 → `240D`），在 openat hook 中对 tcp 文件做同样的行过滤。

**定向过滤原则**：只过滤来自目标安全 SO 调用栈的读取（用 `Thread.backtrace` 判断调用者），不要全局污染 `/proc` 内容。

## 5. dlsym 动态解析拦截（高混淆 SDK）

检测原理：高度混淆的 SDK 不直接导入 `pthread_create`（不在 `.dynsym`），运行时通过 `dlsym` 动态解析（字符串加密存储）。识别：`llvm-readelf --dyn-syms` 无 pthread_create + Binary Ninja 搜不到明文 "pthread_create"。

绕过：在安全 SO 的 dlopen 窗口内 hook `dlsym`，把 `dlsym("pthread_create")` 的返回值替换为受控回调：

```javascript
function hookDlsymBypass(blockedSo, expectedCount) {
	expectedCount = expectedCount || 1;
	var libc = Process.getModuleByName('libc.so');
	var pthreadCreateAddr = libc.getExportByName('pthread_create');
	var realPthreadCreate = new NativeFunction(pthreadCreateAddr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
	var dummyThread = new NativeCallback(function(arg){
		return ptr(0);
	}, 'pointer', ['pointer']);
	var fakePthreadCreate = new NativeCallback(function(thread, attr, startRoutine, arg){
		return realPthreadCreate(thread, attr, dummyThread, ptr(0));
	}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

	var dlsymInterceptor = null;

	function armDlsym() {
		var dlsymAddr = Module.findGlobalExportByName('dlsym');
		if (dlsymAddr === null) return null;
		var count = 0;
		return Interceptor.attach(dlsymAddr, {
			onEnter: function (args) {
				this.isPthreadCreate = false;
				try {
					if (args[1].readCString() === 'pthread_create')
						this.isPthreadCreate = true;
				} catch (e) {}
			},
			onLeave: function (retval) {
				if (this.isPthreadCreate) {
					count++;
					var mod = Process.findModuleByAddress(this.returnAddress);
					var caller = mod ? mod.name + '+0x' + this.returnAddress.sub(mod.base).toString(16) : this.returnAddress;
					console.log('anti-detect: replace dlsym(pthread_create) #' + count + ' caller=' + caller);
					retval.replace(fakePthreadCreate);
					if (count >= expectedCount && dlsymInterceptor !== null) {
						dlsymInterceptor.detach();
						dlsymInterceptor = null;
					}
				}
			}
		});
	}

	['android_dlopen_ext', 'dlopen'].forEach(function (name) {
		var addr = Module.findGlobalExportByName(name);
		if (addr === null) return;
		Interceptor.attach(addr, {
			onEnter: function (args) {
				var p = args[0];
				if (p !== undefined && p !== null && !p.isNull()) {
					var path = p.readCString();
					if (path !== null && path.indexOf(blockedSo) > -1 && dlsymInterceptor === null) {
						console.log('anti-detect: detected ' + blockedSo + ' via ' + name);
						dlsymInterceptor = armDlsym();
					}
				}
			}
		});
	});
}
// 用法：hookDlsymBypass('libmsaoaidsec.so', 3);
```

**关键注意事项**：
- **dlopen 窗口精确控制** — 在 dlopen onEnter 时安装 dlsym hook；卸载时机按样本证据决定（命中次数/构造阶段完成/超时观测）。
- **不要全量替换 pthread_create** — dlopen 窗口内 libart.so 等也会创建正常线程，直接 hook pthread_create 会误杀 ART 运行时线程导致进程终止。
- **自定义链接器的 dlsym 调用也会被拦截** — 只有调用栈和返回地址都指向已确认安全 SO 时才替换结果。

## 6. pthread_create 线程阻断

**工作流：先定位 offset，再 nop。** 检测线程入口偏移的确定有两条途径：

- hook `pthread_create` 探针（§1 第一步）——适用于直接导入并调用 `pthread_create` 的 SDK；
- hook `clone` 探针——**更高级的方式**：有些库的实现绕过 `pthread_create`，通过 `clone` 手动创建线程。`pthread_create` 内部最终也调用 `clone`，线程函数地址存在子线程结构体 +96 偏移处（读取第 4 个参数 + 96），因此 hook `clone` 覆盖面更全，两种线程创建方式都能观测到。

确定检测线程的 offset 后，用本节方式一/方式三 nop 或替换这些线程入口，可以一定程度上绕过检测；未知入口只记录不替换。

**方式一：构造阶段 nop 检测线程入口**（linker `call_constructors` 中，早于 SDK 线程启动）：

```javascript
let alreadyHook = false;

function hook_init_proc() {
  const linker = (Process.pointerSize == 8) ? Process.findModuleByName("linker64") : Process.findModuleByName("linker");
  if (linker) {
    const symbols = linker.enumerateSymbols();
    for (const symbol of symbols) {
      if (symbol.name.includes("call_constructors")) {
        Interceptor.attach(symbol.address, {
          onEnter: function (_args) {
            if (!alreadyHook) {
              const targetSo = Process.findModuleByName("libmsaoaidsec.so");
              if (targetSo) {
                // 已证实偏移的检测函数，nop 掉（偏移来自 pthread_create 探针或逆向）
                nop(targetSo.base, 0x1C544);
                nop(targetSo.base, 0x1B8D4);
                nop(targetSo.base, 0x26E5C);
                alreadyHook = true;
              }
            }
          }
        });
        break;
      }
    }
  }
}

function nop(base, offset) {
  Interceptor.replace(base.add(offset), new NativeCallback(function () {
    console.log(`thread func sub_${offset.toString(16).toUpperCase()} noped`)
  }, 'void', []));
}
```

**方式二：pthread_create 层按模块+偏移阻断**（已知入口时使用）：

```javascript
function hookPthreadCreate(blockedEntries) {
	// blockedEntries格式: [{so: 'libmsaoaidsec.so', offset: 0x1c544}, ...]  offset:-1 表示全部
	var libc = Process.getModuleByName('libc.so');
	var pthreadCreateAddr = libc.getExportByName('pthread_create');
	var pthreadCreate = new NativeFunction(pthreadCreateAddr, 'int',
		['pointer', 'pointer', 'pointer', 'pointer']);

	Interceptor.replace(pthreadCreateAddr, new NativeCallback(
		function(thread, attr, startRoutine, arg) {
			var mod = Process.findModuleByAddress(startRoutine);
			if (mod !== null) {
				var offset = startRoutine.sub(mod.base).toInt32();
				for (var i = 0; i < blockedEntries.length; i++) {
					var entry = blockedEntries[i];
					if (mod.name === entry.so && (entry.offset === -1 || offset === entry.offset)) {
						console.log('anti-detect: block thread ' + mod.name + ' +0x' + offset.toString(16));
						return 0;
					}
				}
			}
			return pthreadCreate(thread, attr, startRoutine, arg);
		},
		'int', ['pointer', 'pointer', 'pointer', 'pointer']
	));
}
```

**方式三：替换目标 so 创建的反调试线程入口**（观测优先，简单场景）：

```javascript
const targetLib = "libcrackme.so";

function main() {
  Interceptor.attach(Process.getModuleByName("libc.so").getExportByName("pthread_create"), {
    onEnter: function(args) {
      const pthreadFunc = args[2];
      try {
        const module = Process.getModuleByAddress(pthreadFunc);
        if (module.name === targetLib) {
          console.log("pthread create by target lib, func addr: ", pthreadFunc);
          Interceptor.replace(pthreadFunc, new NativeCallback(function() {
            console.log("bypass anti-debug function");
            return 0;
          }, 'int', []));
        }
      } catch (_e) {
      }
    },
  });
}

setImmediate(main);
```

**定位补充：clone 探针完整版**（检测线程若绕过 `pthread_create`，用此脚本定位其 offset）：

```javascript
// 有些库的实现绕过pthread_create，通过clone手动创建线程
// IDA分析pthread_create：start_routine存入子线程结构体+96偏移
// v32 = clone(__pthread_start, v18, 4001536LL, v30, ...)
// v30即描述子线程的结构体，+96偏移存储线程函数地址
// 通过读取clone第4个参数+96的地址，可以获取实际执行的线程函数
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

拿到 `module + offset` 后，按方式一在构造阶段 `nop(base, offset)`，或按方式三 replace 该入口。

## 7. 安全 SDK 定向绕过基线

生成定向绕过脚本前先回答四个问题：

- 目标进程死于 `abort`、`exit_group`、`kill/tgkill`、SIGSEGV 还是空 attach 触发？
- 安全 SO 是否被加载，加载路径来自 APK 还是 `app_lib`？
- 检测线程入口来自哪个 SO、哪个偏移？
- 检测是在构造阶段同步执行，还是在线程里异步执行？

三种方案口径：

| 方案 | 适用场景 | 口径 |
|---|---|---|
| 阻断加载 | 快速验证不加载安全库时 App 能否启动 | 最粗，但最快（§2） |
| 轻量定向 | 日常优先和快速回归 | 构造阶段 patch 完整性，定向过滤 maps，替换目标线程 |
| 逆向点定向 | **推荐方案** | 只按已证实 EA 打补丁，未知线程只记录 |

**已证实检测点与处理方式**：

| 类型 | 证据 | 处理方式 |
|---|---|---|
| 构造阶段同步检测 | `call_constructors` 前后触发，Hook 日志能定位到目标 SO 偏移 | 仅 Patch 已证实偏移 |
| 检测线程 | `pthread_create` 的 `start_routine` 来自目标 SO 偏移 | 已确认入口替换为空线程，未知入口只记录 |
| maps 和 smaps 扫描 | `open/openat/read` 调用栈来自目标 SO | 只过滤目标 SO 发起的 `/proc/<pid>/(maps|smaps)` 读取 |
| 退出链路 | `exit/_exit/exit_group/kill/tgkill/abort` 调用栈来自目标 SO | 先记录栈，确认检测点后再决定是否拦截 |

**逆向点定向代码骨架**（arm64）：

```javascript
var TARGET_MODULE = 'libtarget_security.so';
var RET_ZERO_PATCHES = [
	{offset: 0x1234, name: 'constructor_sync_check'}
];
var RET_ONLY_PATCHES = [
	{offset: 0x2345, name: 'confirmed_exit_path'}
];

function patchReturnZero(target){
	Memory.patchCode(target, 8, function(code){
		code.writeU32(0x52800000);        // mov w0, #0
		code.add(4).writeU32(0xd65f03c0); // ret
	});
}

function patchReturnOnly(target){
	Memory.patchCode(target, 4, function(code){
		code.writeU32(0xd65f03c0);        // ret
	});
}

function patchModuleTargets(module){
	RET_ZERO_PATCHES.forEach(function(item){
		patchReturnZero(module.base.add(item.offset));
		console.log('patched ' + item.name + ' offset=0x' + item.offset.toString(16));
	});
	RET_ONLY_PATCHES.forEach(function(item){
		patchReturnOnly(module.base.add(item.offset));
		console.log('patched ' + item.name + ' offset=0x' + item.offset.toString(16));
	});
}
```

线程替换（只替换已证实入口，未知入口只记录）：

```javascript
var BLOCKED_THREAD_OFFSETS = {
	0x3456: 'confirmed_watchdog'
};

var dummyThread = new NativeCallback(function(){
	return ptr(0);
}, 'pointer', ['pointer']);

function hookPthreadCreateForTargetModule(){
	var libc = Process.getModuleByName('libc.so');
	var addr = Module.findGlobalExportByName('pthread_create') || libc.findExportByName('pthread_create');
	if (addr === null) return;
	Interceptor.attach(addr, {
		onEnter: function(args){
			var startRoutine = args[2];
			var mod = Process.findModuleByAddress(startRoutine);
			if (mod === null || mod.name !== TARGET_MODULE) return;
			var offset = startRoutine.sub(mod.base).toUInt32();
			var name = BLOCKED_THREAD_OFFSETS[offset];
			if (name === undefined){
				console.log('unexpected pthread_create offset=0x' + offset.toString(16));
				return;
			}
			args[2] = dummyThread;
			args[3] = ptr(0);
			console.log('redirect pthread_create offset=0x' + offset.toString(16) + ' name=' + name);
		}
	});
}
```

**验收点**：目标 Activity 能进入、Frida 会话存活、探针日志不再出现已确认检测线程或异常退出链、真机与模拟器分别复测。

## 8. Root 检测多路径绕过

按检测证据启用对应路径，不要无差别全局替换。检测面：包名（Magisk/SuperSU/Xposed）、文件（`su`/`busybox`/`magisk`）、系统属性（`ro.debuggable` 等）、命令执行、`test-keys` 标签、native `fopen`。

```javascript
var ROOT_PACKAGES = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'de.robv.android.xposed.installer'];
var ROOT_BINARIES = ['su', 'busybox', 'magisk', 'Superuser.apk'];
var ROOT_PROPERTIES = {
	'ro.debuggable': '0',
	'ro.secure': '1',
	'service.adb.root': '0',
	'ro.build.selinux': '1'
};

// Java 层最小模板
Java.perform(function(){
	var NameNotFoundException = Java.use('android.content.pm.PackageManager$NameNotFoundException');
	var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
	var File = Java.use('java.io.File');
	var SystemProperties = Java.use('android.os.SystemProperties');

	function equalsAny(list, value){
		if (value === null) return false;
		for (var i = 0; i < list.length; i++){
			if (value === list[i]) return true;
		}
		return false;
	}

	var getPackageInfo = ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int');
	getPackageInfo.implementation = function(packageName, flags){
		if (equalsAny(ROOT_PACKAGES, packageName)){
			console.log('root package hidden package=' + packageName);
			throw NameNotFoundException.$new(packageName);
		}
		return getPackageInfo.call(this, packageName, flags);
	};

	var exists = File.exists.overload();
	exists.implementation = function(){
		var name = this.getName();
		if (equalsAny(ROOT_BINARIES, name)){
			console.log('root file hidden name=' + name);
			return false;
		}
		return exists.call(this);
	};

	var getProperty = SystemProperties.get.overload('java.lang.String');
	getProperty.implementation = function(key){
		if (ROOT_PROPERTIES[key] !== undefined){
			console.log('root property patched key=' + key);
			return ROOT_PROPERTIES[key];
		}
		return getProperty.call(this, key);
	};
});

// native 层（确认目标走 native 检测时才启用）
function hookNativeRootChecks(){
	function isRootPath(path){
		if (path === null) return false;
		return path.indexOf('/su') !== -1 || path.indexOf('busybox') !== -1 ||
			path.indexOf('magisk') !== -1 || path.indexOf('Superuser.apk') !== -1;
	}

	var fopen = Module.findGlobalExportByName('fopen');
	if (fopen !== null){
		Interceptor.attach(fopen, {
			onEnter: function(args){
				if (args[0] === undefined || args[0] === null || args[0].isNull()) return;
				var path = args[0].readCString();
				if (isRootPath(path)){
					console.log('native root fopen hidden path=' + path);
					args[0] = Memory.allocUtf8String('/system/bin/does_not_exist');
				}
			}
		});
	}
}
```

Root 绕过和 Frida 反检测分开启用，避免日志和行为难以归因。

## 9. 模拟器 EGL 崩溃处理

Frida 注入改变进程内存布局，模拟器 RenderThread 初始化 EGL 时 `EGL_NOT_INITIALIZED` → `abort()`。**这不是反检测**。识别：探针日志 `abort()` backtrace 包含 `libhwui.so`。

```javascript
function hookEglAbort() {
	var libc = Process.getModuleByName('libc.so');
	// 崩溃相关模块白名单 — 来自这些模块的退出调用改为挂起线程
	var crashModules = ['libhwui.so', 'liblog.so', 'libBugly.so'];

	function isFromCrashModule(context) {
		var bt = Thread.backtrace(context, Backtracer.ACCURATE);
		for (var i = 0; i < bt.length; i++) {
			var mod = Process.findModuleByAddress(bt[i]);
			if (mod !== null) {
				for (var j = 0; j < crashModules.length; j++) {
					if (mod.name === crashModules[j]) return mod.name;
				}
			}
		}
		return null;
	}

	Interceptor.attach(libc.getExportByName('abort'), {
		onEnter() {
			var src = isFromCrashModule(this.context);
			if (src !== null) {
				console.log('anti-detect: suppress abort from ' + src);
				Thread.sleep(999999);
			}
		}
	});

	['_exit', 'exit_group'].forEach(function(name) {
		var addr = libc.findExportByName(name);
		if (addr === null) return;
		Interceptor.attach(addr, {
			onEnter(args) {
				var src = isFromCrashModule(this.context);
				if (src !== null) {
					console.log('anti-detect: suppress ' + name + ' from ' + src);
					Thread.sleep(999999);
				}
			}
		});
	});
}
```

EGL 崩溃不能当作反检测成功或失败的唯一证据，最终用真机复测。

## 10. VPN 检测三路径绕过

覆盖三条路径：`NetworkInterface` 接口名、旧版 `TYPE_VPN(17)`、新版 `TRANSPORT_VPN(4)`：

```javascript
Java.perform(function(){
	var SystemClass = Java.use('java.lang.System');
	var NetworkInterface = Java.use('java.net.NetworkInterface');
	var ConnectivityManager = Java.use('android.net.ConnectivityManager');
	var NetworkInfo = Java.use('android.net.NetworkInfo');
	var NetworkCapabilities = Java.use('android.net.NetworkCapabilities');
	var vpnInfoIds = {};

	function isVpnInterfaceName(name){
		return name === 'tun0' || name === 'ppp0' || name.indexOf('tun') === 0;
	}

	var getName = NetworkInterface.getName.overload();
	getName.implementation = function(){
		var name = getName.call(this);
		if (isVpnInterfaceName(name)){
			console.log('vpn interface renamed name=' + name);
			return 'wlan0';
		}
		return name;
	};

	var getNetworkInfo = ConnectivityManager.getNetworkInfo.overload('int');
	getNetworkInfo.implementation = function(type){
		var result = getNetworkInfo.call(this, type);
		if (type === 17 && result !== null){
			var id = String(SystemClass.identityHashCode(result));
			vpnInfoIds[id] = true;
		}
		return result;
	};

	// 标志位在 isConnected 后立即清除，不永久污染全局状态
	var isConnected = NetworkInfo.isConnected.overload();
	isConnected.implementation = function(){
		var id = String(SystemClass.identityHashCode(this));
		if (vpnInfoIds[id] === true){
			delete vpnInfoIds[id];
			return false;
		}
		return isConnected.call(this);
	};

	var hasTransport = NetworkCapabilities.hasTransport.overload('int');
	hasTransport.implementation = function(transportType){
		if (transportType === 4){
			console.log('vpn transport hidden');
			return false;
		}
		return hasTransport.call(this, transportType);
	};
});
```

## 11. inline svc syscall 对抗（高强度 RASP）

DexProtector 等高强度保护**不走 libc**，直接 inline `svc #0` 发起 syscall，Interceptor 对 libc 的一切 hook 全部无效。

> **⚠️ 实战警告：Stalker 是双刃剑，先确认数据真的"脏"再上 Stalker（见 §14）**
>
> 实测案例（爱加密壳，Android 12 arm32，frida 16.5.1）：壳的 inline svc 检查读取 `/proc/self/status`，而 **frida 16.x spawn+resume 之后并不保持 ptrace，TracerPid 实测为 0**——壳读到的是干净数据，根本不需要过滤。此时上 Stalker 反而造成致命反噬：壳的解包代码使用 `cacheflush` 自修改 + 重定位，Stalker 重编译陈旧代码块导致指针损坏，Java/JIT 初始化阶段确定性 SIGSEGV（毒化崩溃）。移除 Stalker、让壳的检查读到真实干净数据后，spawn 全流程直接通过。
>
> **决策顺序**：空 attach 死 → 先看死法（§14 死法归因表）。若是 inline svc 自杀（exit/kill 链）才需要 Stalker 过滤；若是延迟毒化 SIGSEGV 或 TracerPid 本来就是 0，优先尝试"最小干预"路线（无 Stalker + 检测线程阻断 + 让壳自然解包），而不是堆 Stalker。

**识别特征**：
1. 所有 hook 安装成功但无任何日志输出，App 立即死亡；`ApplicationExitInfo` 显示 `exit_self_*` 自杀。
2. **空 attach 也死**（不加载任何脚本，仅 ptrace attach 就触发）：`python3 -c "import frida; s = frida.get_usb_device().attach(<pid>); time.sleep(3)"` — ptrace 使 `TracerPid != 0`，目标用 inline svc 读 status 检测后 `tgkill` 自杀。
3. 二进制含大量裸 svc 指令：`llvm-objdump -d <target>.so | grep svc`（arm64 `svc #0` 编码 = `01 00 00 d4`）。

**aarch64 反检测常用 syscall号**（x8 寄存器存号，参数 x0..x5）：

| 号 | 名称 | 用途 |
|----|------|------|
| 56 | `openat` | 读 `/proc/self/status`、maps、mem |
| 63 | `read` | 读 TracerPid、maps、cmdline |
| 78 | `readlinkat` | 读 `/proc/self/exe` |
| 94 | `exit_group` | **整个进程退出（最常用自杀）** |
| 131 | `tgkill` | **同进程内自杀** |
| 167 | `prctl` | `PR_SET_DUMPABLE,0` 反 dump |
| 222/226 | `mmap`/`mprotect` | 匿名可执行区域 |

**Stalker SVC trampoline 拦截**：追踪目标库所有指令，对每条 `svc` 插 callout，由 JS 判定拦截：

```javascript
'use strict';

const SYS_NAMES = {
	56: 'openat', 63: 'read', 78: 'readlinkat',
	93: 'exit', 94: 'exit_group', 129: 'kill', 130: 'tkill', 131: 'tgkill',
	167: 'prctl', 222: 'mmap', 226: 'mprotect'
};

var targetBase = null;
var targetEnd  = null;
var stalkerArmed = false;
var killCount = 0;

function svcCallout(ctx) {
	var num = ctx.x8.toInt32();
	var name = SYS_NAMES[num] || ('syscall_' + num);
	var pc = ctx.pc;

	if (targetBase && pc.compare(targetBase) >= 0 && pc.compare(targetEnd) < 0) {
		var off = pc.sub(targetBase).toInt32();
		console.log('[svc] +0x' + off.toString(16) + ' ' + name + ' #' + num +
			' x0=' + ctx.x0 + ' x1=' + ctx.x1);

		// 拦截自杀syscall：把 x8 改为非法值让内核返 ENOSYS
		if (num === 93 || num === 94 || num === 129 || num === 130 || num === 131) {
			killCount++;
			console.log('[svc] BLOCKING ' + name + ' #' + killCount);
			ctx.x8 = ptr(0xffff);  // invalid syscall number → ENOSYS
		}

		// openat/readlinkat 显示路径
		if (num === 56 || num === 78) {
			try { console.log('   path: ' + ctx.x1.readCString(128)); } catch (e) {}
		}
	}
}

function armStalker() {
	if (stalkerArmed) return;
	stalkerArmed = true;
	var tid = Process.getCurrentThreadId();
	Stalker.follow(tid, {
		transform: function (iterator) {
			var inst;
			while ((inst = iterator.next()) !== null) {
				if (inst.mnemonic === 'svc') {
					iterator.putCallout(svcCallout);
				}
				iterator.keep();
			}
		}
	});
}

// 在目标库dlopen完成时arm stalker
var TARGET_LIB = 'libtarget.so';
var dlopenAddr = Module.findGlobalExportByName('android_dlopen_ext') ||
                 Module.findGlobalExportByName('dlopen');
Interceptor.attach(dlopenAddr, {
	onEnter(args) {
		try {
			var name = args[0].readCString();
			if (name && name.indexOf(TARGET_LIB) !== -1) this.isTarget = true;
		} catch (e) {}
	},
	onLeave() {
		if (!this.isTarget) return;
		var m = Process.findModuleByName(TARGET_LIB);
		if (!m) return;
		targetBase = m.base;
		targetEnd  = m.base.add(m.size);
		armStalker();
	}
});
```

**成本与局限**：性能开销大（每条指令重编译，热路径慢 10-100x）；检测线程若在 `Stalker.follow` 之前已跑过检测 svc 则无法拦截，必须先于目标 init 安装；跨线程检测需对每个新线程 follow（结合 pthread_create hook 或 `Process.attachThreadObserver`）。

**DT_DEBUG / r_debug 检测**：保护壳读动态链接器 `r_debug.r_brk`（`_dl_debug_state`）前 4 字节校验（arm64 原始字节 `5F 24 03 D5` = `BTI c` + `C0 03 5F D6` = `RET`），Frida 注入会覆盖这些字节。通用对抗：init 前构造 fake r_debug（`r_version=1`，`r_brk` 指向含 `BTI c; RET` 的假函数），写入目标库存储 r_debug 指针的全局变量（偏移需逆向目标壳后填入）。

**NativeFunction 的 ADR 陷阱**：调用含 `adr xN, 0x0` 的函数时，trampoline 改变 PC上下文导致 `xN` 变 0（报 `access violation accessing 0x20`）。处理：改调不依赖 adr 的内层函数 / `Stalker.exclude()` 排除该模块 / `Memory.patchCode` 改写 adr。

## 12. Zygisk 方案（强对抗的唯一可靠路径）

当空 attach 即死（ptrace 本身被检测）时，所有 Frida 攻击面失效，必须走 Zygisk pre-fork 注入：无 ptrace（子进程从 Zygote 继承）、更早注入（先于保护壳代码）、可隐藏全部痕迹。

工具链：Magisk（启用 Zygisk）→ ZygiskNext → Shamiko（root 隐藏）→ ZygiskFrida / frida-gadget injector。使用流程：

```bash
# 1. 安装Magisk → 启用Zygisk
# 2. 安装ZygiskNext + Shamiko + ZygiskFrida 模块
# 3. 把目标app加入"deny list"或"target list"
# 4. 重启设备 → 启动目标app
# 5. frida-tools 直接attach（实际通过Zygisk-frida-gadget通信）
frida-ps -U
frida -U -n <pkg> -l <agent.js>
```

自写 Zygisk 模块在 `postAppSpecialize` 阶段注入（比目标库更早）：

```cpp
class FridaInjector : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { mApi = api; }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 此时已在目标app进程内，尚未dlopen任何业务库
        dlopen("/data/local/tmp/frida-gadget.so", RTLD_NOW);
    }
};
REGISTER_ZYGISK_MODULE(FridaInjector)
```

**仍可能失败**：检测 Magisk/Zygisk 自身痕迹（mount/cgroup）→ 加 Shamiko；TEE/TrustZone 远程 attest、Google Play Integrity 强校验 → Zygisk 无法绕过。

## 13. 隐藏 SO 模块定位（calibrate）

某些壳的核心库被 loader 解密解压后写入**匿名 r-x 区域**，不在标准模块列表中（`findModuleByName` 返回 null）。通过匿名 r-x 范围定位并 dump：

```javascript
function findHiddenLib() {
	// 找匿名 r-x 区域，大小在 0x80000..0x200000 之间
	var candidates = Process.enumerateRanges('r-x').filter(function (r) {
		return r.size > 0x80000 && r.size < 0x200000 && !r.file;
	});
	candidates.forEach(function (r) {
		console.log('    ' + r.base + ' size=0x' + r.size.toString(16));
	});
	return candidates;
}

setTimeout(function () {
	var ranges = findHiddenLib();
	if (ranges.length === 0) return;
	ranges.sort(function (a, b) { return b.size - a.size; });
	var top = ranges[0];

	// dump供host端Binary Ninja分析（按 raw aarch64 加载）
	var ts = new Date().toISOString().replace(/[:.]/g, '-');
	var path = '/data/local/tmp/hidden_lib_' + ts + '.bin';
	var f = new File(path, 'wb');
	var CHUNK = 0x10000;
	var off = 0;
	while (off < top.size) {
		var sz = Math.min(CHUNK, top.size - off);
		try {
			f.write(top.base.add(off).readByteArray(sz));
		} catch (e) {
			f.write(new ArrayBuffer(sz));  // 跳过不可读，写零
		}
		off += sz;
	}
	f.close();
	console.log('[+] wrote ' + top.size + ' bytes to ' + path);
}, 3000);
```

**间接定位**：若 loader 自身可见，先静态逆向找出其全局变量偏移与核心库内已知函数偏移，再回推核心库基址：`core_base = loader.base.add(GLOBAL_OFF).readPointer().sub(CORE_KNOWN_FN_OFF)`。

## 14. 实战复盘：爱加密壳（Ijiami）延迟毒化与最小干预路线（arm32 成功样本）

18 轮迭代换来的完整方法论。目标：`com.webank.wemoney`（爱加密壳，`libexec.so`/`libexecmain.so`，armeabi-v7a，Android 12，frida 16.5.1）。前 17 轮失败的根因不是检测太强，而是**把不需要对抗的东西对抗了**。

### 14.1 死法归因表（比 §1 更完整，先归因再动手）

| 现象 | 结论 | 处理方向 |
|---|---|---|
| `logcat` 出现 `Fatal signal 11 (SIGSEGV), fault addr 0xXXXXXXXX`，且**多次运行 fault addr 完全相同** | 延迟毒化：壳检测到痕迹后不立刻退出，而是把一个指针写坏，让 Java/JIT 初始化阶段"自然"崩溃 | 见 14.3 毒化处理；更要紧的是找出触发毒化的干扰源并移除（14.2） |
| tombstone `pc` 在 `/memfd:jit-cache`，解引用固定坏指针 | 毒化落点在 Java 层 | 同上；`ldrb rN, [r6, r10]` 类字节串循环是典型毒化消费点 |
| 进程变 zombie（`ps` 显示 `Z` 状态，VSZ/RSS=0） | 已死亡且未被 zygote 回收，无声无息 | 同样去 logcat 查 `exited due to signal N`，SIGKILL=外部杀（看门狗线程/子进程），SIGSEGV=毒化或真实崩溃 |
| libc 层 `exit/_exit/exit_group/kill/tgkill/abort` 全部无触发但进程死 | inline svc 自杀 或 毒化 SIGSEGV | 二者区分看 logcat signal 号：9=自杀/外部杀，11=毒化/崩溃 |
| 空 attach（零脚本）也死 | **不一定需要 Zygisk**！先确认死亡机制 | 若为毒化 SIGSEGV：说明壳对 frida 驻留痕迹敏感，走 14.2 最小干预，而不是直接上 Zygisk |
| `adb shell "ps -A"` 看到应用换了 pid 仍存活 | spawn 的进程死了但应用的 keep-alive 把自己拉起来了 | dump 窗口内抓到的数据已有效，别被"死了"迷惑 |

### 14.2 核心教训：最小干预优先于全面对抗

**先确认检测读取的数据是否真的"脏"**。frida 16.x `spawn + resume` 之后**并不保持 ptrace**——实测壳逐字节读取真实 `/proc/self/status` 时 `TracerPid` 本来就是 0（可通过对 `read` 返回内容与本地 `readAllReal` 做差分验证，`diffs=0` 即铁证）。数据干净时，壳的检查自然通过，什么都不用过滤。

**Stalker 反噬机制**（17 轮失败的总根因）：壳的解包代码是自修改的（大量 `cacheflush` syscall、匿名 `rwx` 区域、mprotect 解锁/上锁序列）。Stalker 对其重编译后：

1. 壳执行到已被修改/重定位的代码时，执行的是 Stalker 的**陈旧代码块副本**；
2. 重定位计算出的指针落进 Stalker slab 或指向陈旧布局；
3. 壳的后续检查发现"不对劲"（或直接用了坏指针），触发**延迟毒化**——不在 native 层退出，而是写坏一个 Java 层稍后要用的指针，让 Java/JIT 初始化阶段确定性 SIGSEGV，极具迷惑性。

**判断指标**：堆 Stalker/伪造/过滤类绕过后死亡时间点反而**提前**或死亡形态**不变**（同一 fault addr），说明干扰源就是你的绕过本身。正确动作是做减法。

**成功配方（v18，最终通过）**：

1. **无 Stalker**——壳的 inline svc 检查读到真实干净数据，自然通过；
2. `pthread_create` replace，**只阻断已证实偏移**的检测线程（`libexec.so +0x27129/+0x27159`），未知偏移放行（逆向点定向口径）；
3. DEX hook（`ClassLinker::RegisterDexFile`/`LoadMethod` + `libdexfile OpenCommon`）在 `Java.perform` 前装好；
4. spawn 启动，壳自然解包 → 类加载阶段 hook 自然触发 → dump 全部落地。

**失败配方备忘（不要重蹈）**：

| 尝试 | 结果 | 教训 |
|---|---|---|
| Stalker SVC callout 全套（exit 拦截/clone 伪造/虚拟文件/真实读消毒） | 全部死于同一毒化地址 | 对自修改壳用 Stalker 本身就是污染源 |
| 虚拟文件服务（open 时建干净内容缓冲，read 按偏移供给） | 壳 1 字节即停、提前毒化 | 壳能感知 svc 被跳过；且逐字节 read 场景下按缓冲区正则过滤根本不命中 |
| callout 内调用 NativeFunction（realRead/realOpen/readlink） | 同样毒化 | callout 内尽量零 Native 调用；确需调用要实测验证 |
| 阻断/暂停检测线程后用 `return 0` 伪装 pthread_create 成功 | 秒死 | 壳会校验线程存在性；伪装成功不如放行（那些"检测线程"常兼解包工作线程） |
| `Thread.sleep` 放在 NativeCallback 里当线程桩 | 秒死（JS 锁被持有 30s 全进程冻结） | 线程桩必须用纯 native 入口（如 libc `pause()` 地址），零 JS 参与 |
| 用非法 syscall 号（r7/x8=0xffff）拦截 exit | SIGSYS（signal 31, SYS_SECCOMP）秒死 | 壳装了 seccomp 过滤器，非法 syscall 直接触发 TRAP；拦截 exit 应跳过指令（`ctx.pc += inst.size`）而非改号 |
| `vfork` 与 `fork` 用 `Interceptor.replace` 各替换一次 | `Error: already replaced this function` | bionic 中两者同址，先探测地址再去重；replace 包 try/catch 防脚本中断 |
| arm32 上 hook `__errno_location` 设 errno | `unable to find export '__errno_location'`，脚本中断后续 hook 全没装 | arm32 bionic 是 `__errno`，glibc/arm64 才是 `__errno_location`；脚本顶层调用 NativeFunction 前必须 try/catch，一处抛异常会中断整个加载 |
| Java hook `InMemoryDexClassLoader` 用 `ByteBuffer.allocate(...).put(buf)` 拷贝 | **消耗了原 buffer 的 position**，壳用被清空的 buffer 建 dex 失败后自杀 | hook Java NIO Buffer 必须用 `buf.duplicate()` 副本读取，绝不能动原 buffer 的 position/mark |

### 14.6 多 SDK 场景：零干预对照实验与杀手归因

App 同时集成多个安全 SDK 时（如爱加密 + MSA `libmsaoaidsec.so` + 信鸽 `libxgVipSecurity.so` + 腾讯 TM/图灵盾），**用户点名的 SDK 未必是杀手**。归因流程：

1. **全量线程观测**：`pthread_create` 用 `Interceptor.attach`（非 replace）打印所有非 ART 模块的线程创建（模块名+偏移），建立"谁创建了线程"的完整清单；
2. **零干预对照实验**：去掉一切 replace/block（纯观测），记录死亡时点与位置。若零干预与全量对抗死于同一位置 → 杀手是壳自身逻辑，与你的 hook 无关；
3. **一次一变量**：每轮只改一个 hook，死亡时点是否变化是唯一归因依据。

**爱加密案例的最终归因链**（v18-v25 共 8 轮对照）：

- 杀手是**壳自己的两个检测线程**（`libexec.so +0x27129/+0x27159`）——它们一运行就用 inline svc 扫描 frida-agent 内存映射，发现即自杀；MSA/信鸽/TM/图灵盾的线程**根本没来得及创建**；
- 死亡与 pthread hook 形式无关：block、放行、wrap+Stalker、零干预 attach，全部死于线程创建后同一时刻；
- 晚 attach（App 正常启动后 attach）被 **attach 的 ptrace 瞬态**拒绝：`pidof` 拿到 pid 到 `device.attach` 完成之间进程已死（周期性轮询检测），说明壳 det 线程是常驻轮询型；
- `dmesg` 中壳还探测 `mikrom` 系统服务（ROM 级注入框架检测）——设备若为 MikROM 系 ROM，ROM 级注入（内核隐藏、无 ptrace）是唯一能保持进程存活的路线，Zygisk 次之；
- **spawn 进程死亡但 dump 已完成 ≠ 失败**：dump 发生在类加载早期（壳解包完成后立即），死亡时点在 dump 之后，产物照样有效。

**对"inline svc 扫自身内存映射"型检测的通用结论**：frida-agent 的内存映射是注入的必然产物，svc 绕过一切 libc hook，Stalker 跟踪壳代码又会毒化（§14.2）——普通 frida 注入（spawn/attach/gadget 重打包）在此类检测面前均无解，必须换注入方式（Zygisk pre-fork / ROM 级内核隐藏注入）。

### 14.3 延迟毒化的定点兜底（Process.setExceptionHandler）

即使做好减法，也可加一道保险：只认领毒化窗口的 SIGSEGV，在崩溃地址 `mmap` 全零页后恢复执行，其余异常（ART 的隐式空指针检查等海量正常 SIGSEGV）全部放行：

```javascript
var POISON_LO = 0xb5800000;	// 实测毒化崩溃地址 0xb580e696 所在窗口，跨运行确认后配置
var POISON_HI = 0xb5900000;
var libc = Process.getModuleByName('libc.so');
var mmapFn = new NativeFunction(libc.getExportByName('mmap'),
	'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'int']);

Process.setExceptionHandler(function (details) {
	if (details.type !== 'access-violation') return false;
	var addr = (details.memory !== null && details.memory !== undefined) ? details.memory.address : null;
	if (addr === null) return false;
	var a = addr.toInt32 ? addr.toInt32() : parseInt(addr.toString());
	if (a < POISON_LO || a >= POISON_HI) return false;	// 只认领毒化窗口
	if (Process.findRangeByAddress(addr) !== null) return false;	// 已有映射的不碰
	var pageBase = a & ~0xfff;
	// MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED = 0x32，PROT_READ|WRITE = 3
	var p = mmapFn(ptr(pageBase), 0x1000, 3, 0x32, -1, 0);
	if (p.toInt32() === -1) return false;
	console.log('poison fault mapped page=' + ptr(pageBase) + ' pc=' + details.context.pc);
	return true;	// 恢复执行，假指针解引用读到全零（空串），解析循环正常终止
});
```

要点：

- 过滤条件必须精确到地址窗口 + `findRangeByAddress` 为空，否则会吞掉 ART 的正常空指针检查；
- 窗口值来自**多次运行 tombstone 中完全一致的 fault addr**（ASLR 地址每次都变，固定值才是毒化标记）；
- 若同一毒化指针被反复读取，可在窗口页内填充 `0x00`（空串）或 `0x0a`（换行符，让逐字节解析循环终止）。

### 14.4 arm32 差异速查（对照 §11 的 aarch64 表）

| 项目 | aarch64 | arm32（armeabi-v7a） |
|---|---|---|
| syscall 号寄存器 | `x8` | `r7`（Stalker callout 中 `ctx.r7.toInt32()`） |
| `svc #0` 编码/长度 | `01 00 00 d4`，4 字节 | ARM 模式 `00 00 00 ef`，4 字节；Thumb 模式 `00 df`，**2 字节**——skip 指令时必须用 `transform` 里的 `inst.size`，不能写死 |
| `exit`=1 / `exit_group`=248 / `tgkill`=268 / `openat`=322 | 同 | 同（arm32 EABI 与 aarch64 常用号一致，但 `clone`=120、`fork`=2、`vfork`=190 是 arm32 特有需要关注的号） |
| `cacheflush` | 无 | `__ARM_NR_cacheflush = 0x0f0002`（r7 读出 983042 即它，**放行别拦**，拦了自修改代码执行就废了） |
| `art::DexFile` 布局 | +0 vptr，+8 `begin_`，+16 `size_` | +0 vptr，**+4 `begin_`，+8 `size_`**（`pointerSize=4`） |
| prctl 探测 | `PR_GET_SECCOMP`（nr 167，x8） | 同号 172（arm32 EABI），`r0=3` 调用即为探测 seccomp |

### 14.5 验收清单

- dump 产物落地且通过头部校验（见 `unpack-dump.md` §5）；
- 全程无 `Fatal signal` / `exited due to signal`（或崩溃发生在 dump 完成之后）；
- 壳的检测线程按预期被阻断/放行，日志与预期一致；
- 每轮迭代只改**一个变量**，死亡时间点/死亡形态是否变化作为唯一归因依据——17 轮失败的最大教训就是一次改太多，无法归因。
