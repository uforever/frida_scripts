# DEX 脱壳与 SO dump

## 1. DEX dump：ClassLinker::LoadMethod

hook `libart.so` 的 `ClassLinker::LoadMethod`，第一个业务参数是 DexFile 对象（`args[0]` 是 ClassLinker 本身），按指针大小偏移读取 `begin_` 与 `size_`：

```javascript
function main() {
  const libart = Process.getModuleByName("libart.so");
  const symbols = libart.enumerateSymbols();

  const dexFileSizeSet = new Set();

  // art/runtime/class_linker.cc  ClassLinker::LoadMethod()
  for (const item of symbols) {
    if (item.name.includes("LoadMethod")) {
      const targetFuncAddr = item.address;
      Interceptor.attach(targetFuncAddr, {
        onEnter: function(args) {
          // args[1] 是 DexFile 对象，args[0] 是 ClassLinker 本身
          const dexFilePtr = ptr(args[1]);
          const pointerSize = Process.pointerSize;
          const base = dexFilePtr.add(pointerSize).readPointer();
          const size = dexFilePtr.add(pointerSize * 2).readUInt();
          // 大小相同的DexFile只dump一次
          if (!dexFileSizeSet.has(size)) {
            dexFileSizeSet.add(size);
            console.log(`[Dump DexFile] base: ${base}, length: ${size}.`)
            dumpDexFile(base, size);
          }
        },
      });
    }
  }
}

// 需要先授予应用存储权限；更推荐 send 给 Python 宿主保存（见 §2）
function dumpDexFile(base, size) {
  const path = `/sdcard/Download/${size}.dex`;
  const file = new File(path, "wb");
  file.write(base.readByteArray(size));
  file.flush();
  file.close();
}

setImmediate(main);
```

## 2. DEX dump：RegisterDexFile / LoadMethod / OpenCommon（带宿主保存）

更完整的路线：hook `libart.so` 的 `RegisterDexFile`、`LoadMethod` 与 `libdexfile.so` 的 `OpenCommon`，从 DexFile 指针或 begin/size 读取，按校验和去重，魔数区分 DEX/CDEX，`send` 给 Python 宿主保存：

```javascript
const dexFilePtrSet = new Set();
const checksumSet = new Set();
const pointerSize = Process.pointerSize;

// 添加一些不需要dump的dex文件 如miui mediatek等
checksumSet.add(0x43174B52);
checksumSet.add(0x4480A281);
// ... 按需增删

function dumpDexFileByBeginAndSize(begin, size) {
  // 相同校验和只dump一次
  const checksum = begin.add(8).readU32();
  if (checksumSet.has(checksum)) {
    return;
  }
  checksumSet.add(checksum);
  console.log(`\n[*] Found DexFile\n- begin: ${begin}\n- size: ${size}`);

  const dexMagic = begin.readU32();
  if (dexMagic !== 0x0A786564) { // "dex"
    // 0x78656463 = "cdex" 等：非标准dex打印头部信息后仍可保存供修复
    const headerHexDump = hexdump(begin, { offset: 0, length: 8, header: true, ansi: true });
    console.log(`[!] Not a dex file:\n${headerHexDump}`);
    return;
  }

  const filename = `${checksum.toString(16).toUpperCase().padStart(8, '0')}.dex`;
  console.log(`=> Dump to ${filename}`);
  const data = begin.readByteArray(size);
  send(filename, data);
}

function dumpDexFileByPointer(dexFilePtr) {
  // 每个地址只调用一次（函数回填后地址可能相同，需要时关闭该判断）
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

  const libart = Process.findModuleByName("libart.so");
  const libartSymbols = libart.enumerateSymbols();

  // libdexfile.so 中 hook OpenCommon（较新系统上未经测试，可关闭不影响使用）
  const libdexfile = Process.findModuleByName("libdexfile.so");
  const libdexfileSymbols = libdexfile.enumerateSymbols();

  for (const symbol of libdexfileSymbols) {
    if (symbol.name.includes("OpenCommon")) {
      const targetFuncAddr = symbol.address;
      console.log(`\n[+] Function hooked\n- name: ${symbol.name}\n- offset: ${targetFuncAddr.sub(libdexfile.base)}`);
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          // 名字包含 "OpenCommon" 的函数可能不止一个，前两个参数未必是 begin 和 size
          this.begin = ptr(args[0]);
          this.size = args[1].toInt32();
        },
        onLeave: function (_retval) {
          dumpDexFileByBeginAndSize(this.begin, this.size);
        }
      });
    }
  }

  // libart.so：RegisterDexFile / LoadMethod
  for (const symbol of libartSymbols) {
    if (!symbol.name.includes("DexFile")) continue;
    if (!symbol.name.includes("ClassLinker")) continue;
    // 下面两个函数先不hook
    if (symbol.name.includes("RegisterDexFileLocked")) continue;
    if (symbol.name.includes("RegisterDexFiles")) continue;

    if (symbol.name.includes("RegisterDexFile")) {
      const targetFuncAddr = symbol.address;
      console.log(`\n[+] Function hooked\n- name: ${symbol.name}\n- offset: ${targetFuncAddr.sub(libart.base)}`);
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          dumpDexFileByPointer(ptr(args[1]));
        },
      });
    }

    if (symbol.name.includes("LoadMethod")) {
      const targetFuncAddr = symbol.address;
      console.log(`\n[+] Function hooked\n- name: ${symbol.name}\n- offset: ${targetFuncAddr.sub(libart.base)}`);
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          dumpDexFileByPointer(ptr(args[1]));
        },
      });
    }
  }
}

setImmediate(main);
```

Python 宿主接收并保存：

```python
import os
import sys
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

# usage: python dex_dump.py com.example.app
if __name__ == '__main__':
    package_name = sys.argv[1]
    device = frida.get_device_manager().add_remote_device("127.0.0.1:24486")
    pid = device.spawn([package_name])
    process = device.attach(pid)
    script = process.create_script(jscode)   # jscode 为上面的 JS
    script.on('message', on_message)
    script.load()
    time.sleep(2)
    device.resume(pid)
    sys.stdin.read()
```

**可选增强项**（按需启用，不作默认强制逻辑）：
- dump 前 hook `fork()` 返回 `-1` 并设 `errno=EPERM`，减少子进程干扰。
- `android_dlopen_ext` 阶段记录常见加固 SO（`libDexHelper.so` 等），判断进入 dump 阶段的时机。
- 保存前区分普通 DEX、CDEX（`cdex` 魔数）、空头 DEX 和抹头 DEX；空头或抹头的仍应保存供后续修复。

## 3. SO dump

以 `android_dlopen_ext` 为时机，目标 so 加载完成后整段 dump，`send` 给宿主保存，再用 SoFixer 修复：

```javascript
function soDump(soName) {
  const module = Process.findModuleByName(soName);
  const size = module.size;
  const base = module.base;
  Memory.protect(base, size, 'rwx');
  send({ name: soName, base: base, size: size }, base.readByteArray(size));
}

function libdlHook() {
  const androidDlopenExtAddr = Process.getModuleByName("libdl.so").getExportByName("android_dlopen_ext");
  Interceptor.attach(androidDlopenExtAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        this.filename = path.split('/').pop();
        console.log(`\n[*] libdl.so android_dlopen_ext onEnter\n- file: ${this.filename}\n- path: ${path}`);
        if (this.filename.includes(targetLib)) this.isTarget = true;
      }
    },
    onLeave: function () {
      if (this.isTarget) soDump(targetLib);
    },
  });
}

const targetLib = "libDexHelper.so";   // 替换为实际目标
setImmediate(libdlHook);
```

Python 宿主（注意端口向用户确认，魔改版可能不是 24486）：

```python
import sys
import time
import frida

package_name = ""
so_name = ""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        so_name = payload['name']
        base_addr = payload['base']
        size = payload['size']
        print(f"\n[*] Dump so File\n- name: {so_name}\n- base: {base_addr}\n- size: {size}")
        with open(so_name, "wb") as f:
            f.write(data)
        print("[+] Dumped Successfully")

# usage: python so_dump.py com.example.app libnative-lib.so
if __name__ == '__main__':
    package_name = sys.argv[1]
    so_name = sys.argv[2]
    # 端口与 frida-server 实际监听一致
    device = frida.get_device_manager().add_remote_device("127.0.0.1:24486")
    pid = device.spawn([package_name])
    process = device.attach(pid)
    script = process.create_script(js_script(so_name))
    script.on('message', on_message)
    script.load()
    time.sleep(2)
    device.resume(pid)
    sys.stdin.read()
```

dump 后修复（基址来自 send 的 payload）：

```bash
SoFixer -s libInput.so -o libOutput.so -m 0x70c8db0000
```

也可用 LIEF 等同类工具修复。

## 4. 隐藏 so 定位与 dump

壳的核心库可能被解密解压到**匿名 r-x 区域**，不在 `enumerateModules()` 中。定位方法与完整 dump 代码见 `anti-detection.md` §13（匿名 r-x 范围过滤 + 分块 dump + Binary Ninja raw aarch64 分析）。

## 5. 实战样本：爱加密壳（Ijiami）arm32 脱壳成功配方

目标：`com.webank.wemoney`（爱加密壳 `libexec.so`/`libexecmain.so`，armeabi-v7a，Android 12，frida 16.5.1）。17 轮失败的根因与最终成功配方见 `anti-detection.md` §14——**核心是移除 Stalker 让壳自然解包**，本节只记录 dump 侧要点。

### 5.1 dump 时机与 hook 组合

爱加密壳解包完成后，真实 dex 在**类加载阶段**自然进入 ART，无需主动 dump，三个 hook 点自然触发：

```javascript
// arm32 的 art::DexFile 布局：+0 vptr，+4 begin_，+8 size_（pointerSize=4）
// 与 aarch64（+8/+16）不同，不要写死偏移，用 Process.pointerSize 计算
function dumpDexByPointer(dexFilePtr) {
	var begin = dexFilePtr.add(Process.pointerSize).readPointer();
	var size = dexFilePtr.add(Process.pointerSize * 2).readUInt();
	dumpDexByBeginSize(begin, size);
}
```

hook 点（`libart.so` 枚举符号匹配 `ClassLinker` + `DexFile`）：

- `ClassLinker::RegisterDexFile`（排除 `RegisterDexFileLocked`/`RegisterDexFiles`）——**最早触发点**，dex 刚注册即 dump；
- `ClassLinker::LoadMethod`——兜底；
- `libdexfile.so` 的 `OpenCommon`——`args[0]`=begin、`args[1]`=size，Android 12 上实测有效。

按 checksum（dex header 偏移 8 的 u32）去重；实测一个 23MB 三 dex 的应用在 spawn 后**数秒内**全部落地，远早于壳的检测线程创建。

### 5.2 产物校验清单（dump ≠ 有效，必须校验）

Python 校验脚本要点（`verify_dex.py`）：

```python
magic = data[:8]                                   # b'dex\n039\x00' 等
file_size, = struct.unpack_from('<I', data, 0x20)  # header 自带的 file_size
endian_tag, = struct.unpack_from('<I', data, 0x28) # 标准小端 = 0x12345678（字节序 78 56 34 12）
map_off, = struct.unpack_from('<I', data, 0x34)
string_ids, = struct.unpack_from('<I', data, 0x38) # 合理性：string_ids/type_ids 非零且不夸张
```

- **`file_size == len(data)` 是最强校验**——按 DexFile 结构体里的 size dump 时若指针布局算错，这里立刻暴露；
- endian_tag 常见笔误：标准小端 tag 是 **0x12345678**（字节 `78 56 34 12`），不要写成 0x78563412；
- 非标准魔数：`0x78656463` = `cdex`（compact dex，VDEX 压缩格式），按 §2 的可选增强项保存供修复，或忽略。

### 5.3 宿主与流程要点

- spawn 模式 + hook 在 `Java.perform` 之前安装（时机在壳解包之前）；
- dump 数据走 `send({type:'dex', name, size}, begin.readByteArray(size))`，Python 按 `on_message` 落盘；
- spawn 的进程事后被 SIGKILL/自动重启**不影响结果**——dump 在类加载早期已完成，宿主轮询 `pidof` 时看到 pid 变化属正常；
- 可选兜底：rpc 导出 `Java.choose('dalvik.system.PathClassLoader')` → `pathList.dexElements` → `mCookie`（arm32 下即 `art::DexFile*`）做存活期补 dump。
