# Frida 17 API 约定与完整规范

生成或修改脚本时必须遵守本章。旧 API 已在 Frida 17 中移除，会直接 TypeError。

## 1. 硬性约定：旧 API → 新 API

| 旧写法（禁止） | 新写法 |
|---|---|
| `Module.findExportByName(null, name)` | `Module.findGlobalExportByName(name)`；必定存在时用 `Process.getModuleByName("libdl.so").getExportByName(name)` |
| `Module.findExportByName("libc.so", fn)` | `Process.getModuleByName("libc.so").getExportByName(fn)` |
| `Module.findBaseAddress(lib)` | `Process.getModuleByName(lib).base` |
| `Module.getSymbolByName(null, name)` | `Module.getGlobalExportByName(name)` |
| `Module.enumerateSymbols(lib)` | `Process.getModuleByName(lib).enumerateSymbols()` |
| `Module.enumerateExports(lib)` | `Process.getModuleByName(lib).enumerateExports()` |
| `Memory.readU32(ptr)` / `Memory.writeU32(ptr, v)` | `ptr.readU32()` / `ptr.writeU32(v)`（所有 read/write 类型同理） |
| `Memory.readByteArray(ptr, n)` | `ptr.readByteArray(n)` |
| `Memory.readCString(ptr)` / `Memory.readUtf8String(ptr)` | `ptr.readCString()` / `ptr.readUtf8String()` |
| `Memory.writeUtf8String(ptr, s)` | `ptr.writeUtf8String(s)` |

**find/get 前缀语义**：`find*` 找不到返回 `null`；`get*` 找不到抛异常。

- 必定存在的导出用 `get`（libc/libdl 核心函数如 `pthread_create`、`android_dlopen_ext`），缺失时抛异常快速暴露问题。
- 不确定的导出用 `find`（如目标 so 的 `JNI_OnLoad`），找不到时保持脚本存活。

**版本适配陷阱（17 新 API 在 16.x 上不存在）**：本章 API 以 Frida 17 为基线，但客户端/设备端为 16.x 时（`frida --version` 确认，两端大版本必须一致），17 新 API 会直接 `TypeError: not a function`：

| 17 新 API | 16.x 上的表现 | 16.x 正确写法 |
|---|---|---|
| `Module.findGlobalExportByName(name)` | TypeError（函数不存在） | `Module.findExportByName(null, name)` |
| `Process.attachThreadObserver` | 不存在（实测 16.5.1 返回 undefined） | 无替代；跨线程跟踪改用 `pthread_create` 包裹启动例程后 `Stalker.follow` |
| `Process.attachModuleObserver` | 同上需运行时探测 | `dlopen`/`android_dlopen_ext` hook |

跨版本兼容的标准写法（生成脚本时内置）：

```javascript
function findGlobalExport(name) {
	if (typeof Module.findGlobalExportByName === 'function') {
		return Module.findGlobalExportByName(name);
	}
	return Module.findExportByName(null, name);
}
```

**NativePointer 链式读写**：

```javascript
const playerData = ptr('0x1234');
playerData
  .add(4).writeU32(13)
  .add(4).writeU16(37)
  .add(2).writeU16(42);

const healthAddr = ptr('0x1234');
const health = healthAddr.readU32();
healthAddr.writeU32(100);
```

## 2. Module API

```javascript
// 静态方法 — 全局查找（慢，尽量避免；能指定模块时优先实例方法）
Module.findGlobalExportByName(name)   // 返回 NativePointer | null
Module.getGlobalExportByName(name)    // 同上，找不到抛异常
Module.load(path)                     // 从路径加载模块，失败抛异常

// 实例方法（从 Process.getModuleByName() 或 Process.enumerateModules() 获取）
var mod = Process.getModuleByName('libc.so');
mod.enumerateExports()      // [{type:'function'|'variable', name, address}]
mod.enumerateImports()      // [{type, name, module, address, slot}]
mod.enumerateSymbols()      // [{isGlobal, type, section?, name, address, size?}]
mod.enumerateRanges('r--')  // 限定在本模块内的内存范围枚举
mod.enumerateSections()     // [{id, name, address, size}]
mod.enumerateDependencies() // [{name, type:'regular'|'weak'|'reexport'|'upward'}]
mod.findExportByName(name)  // NativePointer | null（仅搜索该模块）
mod.getExportByName(name)   // 同上，找不到抛异常
mod.findSymbolByName(name)  // NativePointer | null
mod.ensureInitialized()     // 确保模块初始化函数已执行（早期插桩时使用）

// 获取基地址
var base = Process.getModuleByName('libc.so').base;
```

## 3. Process API

```javascript
// 模块查找
Process.findModuleByAddress(addr)   // Module | null
Process.getModuleByAddress(addr)    // 同上，找不到抛异常
Process.findModuleByName(name)      // Module | null
Process.getModuleByName(name)       // 同上，找不到抛异常
Process.enumerateModules()          // Module[]
Process.mainModule                  // 主模块

// 内存范围
Process.findRangeByAddress(addr)    // {base, size, protection, file?} | null
Process.enumerateRanges('rw-')      // 枚举满足保护属性的范围

// 线程
Process.enumerateThreads()
// [{id, name, state, context, entrypoint?}]
Process.getCurrentThreadId()
Process.pointerSize                 // 4 或 8
Process.pageSize
Process.arch / Process.platform
Process.id

// 观察者（新 API，比 dlopen hook 更干净）
var modObs = Process.attachModuleObserver({
    onAdded(module) {},             // 模块加载后、应用代码使用前 — 插桩好时机
    onRemoved(module) {}
});
modObs.detach();

var obs = Process.attachThreadObserver({
    onAdded(thread) {},             // 新线程创建（也会对所有已存在线程立即触发一次）
    onRemoved(thread) {},
    onRenamed(thread, previousName) {}
});
obs.detach();

// 异常处理（慎用：ART 用 SIGSEGV 做空指针检查和 GC，会产生海量调用）
Process.setExceptionHandler(function(details) {
    // details: {type, address, memory?, context, nativeContext}
    return true; // 返回 true 表示已处理
});
```

## 4. Memory / NativePointer

```javascript
// 内存扫描（模式语法：?? 通配，?3 半字节通配）
Memory.scan(base, size, '13 37 ?? ff', {
    onMatch(address, size) { return 'stop'; },  // 可选提前终止
    onError(reason) {},
    onComplete() {}
});
var results = Memory.scanSync(base, size, '13 37 ?? ff');
// [{address, size}]

// 安全修改代码（patchCode 内不要假设 code 与目标地址相同）
Memory.patchCode(targetAddr, 64, function(code) {
    var cw = new Arm64Writer(code, { pc: targetAddr });
    cw.putRet();
    cw.flush();
});

// 保护属性
Memory.protect(addr, 4096, 'rw-');       // 返回 boolean
Memory.queryProtection(addr);            // 'rwx' 类似字符串

// 分配
Memory.alloc(size);
Memory.allocUtf8String(str);

// NativePointer 常用
ptr.isNull();  ptr.add(n);  ptr.sub(n);
ptr.readCString([len]);  ptr.readUtf8String();
ptr.readU8/U16/U32/U64/S8/S16/S32/S64/Float/Double/Pointer();
ptr.writeU8/U16/U32/U64/S8/S16/S32/S64/Float/Double/Pointer(v);
ptr.readByteArray(len);  ptr.writeByteArray(bytes);
```

## 5. Interceptor

```javascript
// attach — onEnter/onLeave 中的 this 字段
Interceptor.attach(target, {
    onEnter(args) {
        this.returnAddress  // NativePointer，调用者地址
        this.context        // CpuContext：{pc, sp, x0..x28, fp, lr}（arm64），可赋值修改
        this.threadId
        this.depth
    },
    onLeave(retval) {
        retval.replace(0);            // 替换返回值为整数
        retval.replace(ptr('0x0'));   // 替换为指针
        // 不要在回调外保存 retval！如需存储：ptr(retval.toString())
    }
});
// 返回监听器对象，可调用 listener.detach()

// replace — 完全替换函数实现
const orig = new NativeFunction(target, 'int', ['pointer', 'int']);
Interceptor.replace(target, new NativeCallback(function(pathPtr, flags) {
    return orig(pathPtr, flags);      // 链式调用原始实现
}, 'int', ['pointer', 'int']));

Interceptor.revert(target);   // 恢复原实现
Interceptor.detachAll();      // 分离所有 hook
Interceptor.flush();          // 立即提交挂起的更改
```

**NativePointer 空值检查**（读写前必须三重检查）：

```javascript
Interceptor.attach(target, {
    onEnter(args) {
        var p = args[0];
        // 必须三重检查：undefined、null、isNull
        if (p !== undefined && p !== null && !p.isNull()) {
            var str = p.readCString();
        }
    }
});
```

**NativeFunction / NativeCallback / SystemFunction**：

```javascript
var fn = new NativeFunction(addr, 'int', ['pointer', 'int'], {
    scheduling: 'cooperative',  // 默认；'exclusive' 更快但可能死锁
    traps: 'default'            // 'none' 可阻止 Interceptor/Stalker 触发
});
// 可变参数：固定参数和可变参数之间加 '...'
var printf = new NativeFunction(addr, 'int', ['pointer', '...', 'int']);
// SystemFunction 返回 {value, errno}
var sysfn = new SystemFunction(addr, 'int', ['pointer', 'int']);
```

## 6. Thread / DebugSymbol / ApiResolver

```javascript
// 调用栈回溯（Interceptor 回调中必须传 this.context）
Thread.backtrace(this.context, Backtracer.ACCURATE)   // 精确，需调试信息
    .map(DebugSymbol.fromAddress).join('\n');
Thread.backtrace(this.context, Backtracer.FUZZY)      // 模糊，无需调试信息

Thread.sleep(0.05);      // 暂停当前线程（秒）
Thread.sleep(999999);    // 永久挂起（反检测中替代 exit）

// 符号解析
DebugSymbol.fromAddress(ptr('0x1234'));               // {name, moduleName, fileName, lineNumber}
DebugSymbol.getFunctionByName('pthread_create');      // 找不到抛异常
DebugSymbol.findFunctionsMatching('pthread_*');

// 名称模式批量查找（比逐模块枚举高效）
var resolver = new ApiResolver('module');
resolver.enumerateMatches('exports:libc.so!pthread*');
resolver.enumerateMatches('exports:*!open*');         // 所有模块
resolver.enumerateMatches('imports:libmsaoaidsec.so!*');
// '/i' 后缀不区分大小写
```

## 7. Stalker

```javascript
// 基本跟踪
Stalker.follow(thread.id, {
    events: { call: true, ret: false, exec: false, block: false, compile: false },
    // onCallSummary：{目标地址: 调用次数} 的 map，性能好
    onCallSummary(summary) {
        for (var addr in summary) console.log(addr + ' x' + summary[addr]);
    },
    // transform：每次重编译基本块时同步调用
    transform(iterator) {
        var instruction;
        do {
            if (iterator.memoryAccess === 'open') {   // ARM 独占存储序列中禁止插代码
                iterator.putCallout(function(context) {
                    console.log('pc=' + context.pc);  // CpuContext 可读写寄存器
                });
            }
            iterator.keep();   // 不调用 keep() 则丢弃该指令
        } while ((instruction = iterator.next()) !== null);
    }
});
Stalker.unfollow(thread.id);
Stalker.flush();
Stalker.garbageCollect();   // unfollow 后安全释放内存

// 排除范围（减少噪音）
var libc = Process.getModuleByName('libc.so');
Stalker.exclude({ base: libc.base, size: libc.size });

// 调用探针
var probeId = Stalker.addCallProbe(targetAddr, function(context) {});
Stalker.removeCallProbe(probeId);
```

arm64 CpuContext 字段：`pc, sp, x0..x28, fp, lr`，均可赋值修改。

## 8. Cloak 隐匿 API

```javascript
// 线程隐匿（对 /proc/<pid>/task/ 枚举等隐藏）
Cloak.addThread(threadId);  Cloak.removeThread(threadId);

// 隐匿 Frida 自身的特征线程
Process.enumerateThreads().forEach(function(t) {
    if (t.name && (t.name.indexOf('gmain') !== -1 || t.name.indexOf('gdbus') !== -1
            || t.name.indexOf('gum-js-loop') !== -1)) {
        Cloak.addThread(t.id);
    }
});

// 内存范围隐匿（不出现在 /proc/self/maps 的 Frida 层视图中）
Cloak.addRange({ base: ptr('0x1000'), size: 0x2000 });
Cloak.removeRange({ base: ptr('0x1000'), size: 0x2000 });

// 文件路径隐匿（对 openat/access/stat 等隐形）
Cloak.addFile('/data/local/tmp/frida-server');
```

## 9. File / SqliteDatabase

```javascript
// 快速读写
var text = File.readAllText('/data/local/tmp/log.txt');
File.writeAllText('/data/local/tmp/log.txt', 'hello');

// 流式
var f = new File('/sdcard/Download/out.bin', 'wb');
f.write(base.readByteArray(size));
f.flush();
f.close();

// SqliteDatabase（日志持久化）
var db = SqliteDatabase.open('/data/local/tmp/hooks.db', { flags: ['readwrite', 'create'] });
db.exec('CREATE TABLE IF NOT EXISTS events (ts INTEGER, module TEXT, offset INTEGER)');
var stmt = db.prepare('INSERT INTO events VALUES (?, ?, ?)');
stmt.bindInteger(1, Date.now()); stmt.bindText(2, 'libmsaoaidsec.so'); stmt.bindInteger(3, 0x1c544);
stmt.step(); stmt.reset();
db.close();
```

## 10. Java 桥接常用

```javascript
Java.available                 // Java 运行时是否可用
Java.perform(fn)               // 调度到 Java 上下文执行
Java.performNow(fn)            // 立即执行（已在 Java 线程时）
Java.use(className)            // 获取类包装
Java.choose(className, {onMatch, onComplete})   // 枚举堆上实例
Java.cast(obj, Class)          // 类型转换
Java.retain(obj)               // 脱离回调作用域保留对象
Java.array('java.lang.String', ['a', 'b'])
Java.registerClass({name, implements, methods})
Java.enumerateLoadedClasses({onMatch, onComplete})
Java.enumerateClassLoaders({onMatch, onComplete})
Java.enumerateMethods('*!check')   // 按模式批量查方法
Java.scheduleOnMainThread(fn)
Java.ClassFactory.get(loader)  // 用指定 ClassLoader 创建工厂（壳场景必用）
Java.vm.tryGetEnv()            // Native 上下文中获取 JNIEnv
```

`Java.choose`/`enumerateLoadedClasses`/`enumerateClassLoaders` 的回调中 `onComplete` **必须写**（空函数也行），否则报错。
