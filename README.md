# frida_scripts

Frida 安卓逆向脚本集合。所有脚本已迁移至 **Frida 17.x** 新版 API。

## 内容索引

### Java 层基础

| 脚本 | 能力说明 |
|---|---|
| [sample.js](sample.js) | Java 层 hook 基础：`Java.use`、静态/实例/构造方法、内部类、动态加载类 loader 的各种 hook 写法 |
| [sample2.js](sample2.js) | `Java.choose` 实例搜索、主线程调度、手动 `$new` 创建实例并调用方法 |
| [mTracer.js](mTracer.js) | 批量 Java 方法追踪：按包名/类名过滤，输出参数、调用栈、返回值，适合调用链分析 |
| [eventWatcher.js](eventWatcher.js) | UI 事件监听：hook `View.setOnClickListener` 追踪点击事件与监听器类名 |
| [launchActivity.js](launchActivity.js) | 通过 `ActivityThread` + `Intent` 启动指定 Activity |

### Native 层基础

| 脚本 | 能力说明 |
|---|---|
| [nativeTimeout.js](nativeTimeout.js) | native 层 hook 入门：延迟等待 so 加载，枚举符号定位未导出函数 |
| [nativeLog.js](nativeLog.js) | 以 `android_dlopen_ext` 时机 hook so 内多个加密函数，打印输入输出 |
| [modifyRetval.js](modifyRetval.js) | 时机 hook + 修改 native 函数返回值（`retVal.replace`） |
| [nativeImmediate.js](nativeImmediate.js) | 时机 hook + `NativeFunction`/`NativeCallback` 篡改函数参数后再调用原函数 |
| [nativeInvoke.js](nativeInvoke.js) | 根据基址 + offset 主动调用 native 函数（`NativeFunction`） |
| [elfHook.js](elfHook.js) | 定位 so 内未导出函数地址，`Interceptor.attach/replace` 替换加解密逻辑并篡改参数 |
| [readMemory.js](readMemory.js) | 内存读取示例：基址 + offset 的 `readCString`、`readPointer` 链式读取 |
| [nativeRegister.js](nativeRegister.js) | JNI 动态注册监控：hook `libart.so` 的 `RegisterNativeMethod`，输出方法名、签名、so 偏移 |
| [nativeTrace.js](nativeTrace.js) | hook `libart.so` 导出函数辅助追踪，配合基本块打印辅助分析 ollvm |
| [stalkerTrace.js](stalkerTrace.js) | `Stalker.follow` 跟踪主程序指令流：反汇编 + 寄存器上下文输出 |
| [hookClone.js](hookClone.js) | hook `libc.so` 的 `clone`，读取线程启动函数地址并解析所属模块与偏移 |

### 时机 hook 与线程

| 脚本 | 能力说明 |
|---|---|
| [inShell.js](inShell.js) | 加壳应用 hook：`Application.attach` 中获取 `ClassLoader` 并通过 `Java.ClassFactory.get` 定位壳内业务类 |
| [nopThreadFunc.js](nopThreadFunc.js) | 两种 nop 线程检测函数的方式：`Arm64Writer.putRet` 与 `Interceptor.replace`，配合 linker `call_constructors` 提前 hook |
| [patchCode.js](patchCode.js) | `Memory.patchCode` + `Arm64Writer` 将调用 `pthread_create` 的指令 nop 掉，绕过 hook 检测 |
| [pthreadBypass.js](pthreadBypass.js) | hook `pthread_create` 识别目标 so 创建的反调试线程并替换其入口函数 |

### 反检测绕过

| 脚本 | 能力说明 |
|---|---|
| [bypassAnti.js](bypassAnti.js) | 针对阿里安全 SDK（libmsaoaidsec.so，如 bili/soul/xhs）的反调试绕过：linker 构造阶段 nop 检测函数 + `fgets`/`strstr`/`access` 通用绕过 |
| [regularBypass.js](regularBypass.js) | 通用 Frida 检测绕过基础：linker64 `call_constructors` 时机监控 + `fgets`/`strstr`/`strcmp`/`access`/`connect`/`open` 全套 libc 层关键字过滤与 `/proc` 重定向 |
| [mixUse.js](mixUse.js) | 综合利用：bypassAnti 的反检测 + 完整 SSL unpinning（OkHttp/Conscrypt/TrustManager/Xutils 等多框架）+ okhttp RealConnection 类自动发现 |
| [bypass_key_attest.js](bypass_key_attest.js) | 硬件密钥证明（Key Attestation）绕过测试案例 |

### 网络与证书

| 脚本 | 能力说明 |
|---|---|
| [okHttpSslUnpinning.js](okHttpSslUnpinning.js) | OkHttp 公钥固定绕过：`sslSocketFactory`/`build`/`certificatePinner` + 系统 `NetworkSecurityTrustManager` |
| [unpinMore.js](unpinMore.js) | 更全面的 SSL unpinning：Java/Android/OkHttp/Conscrypt/Apache/Xutils 多框架，含轻度混淆对抗 |
| [certificateExport.js](certificateExport.js) | 双向 TLS 客户端证书导出：hook `KeyStore$PrivateKeyEntry` 导出私钥与证书链为 PKCS12 |
| [socketHook.js](socketHook.js) | socket 抓包：Java 层 `Socket`/TCP/UDP 读写 + native `SSL_read`/`SSL_write` 明文拦截 |

### 算法与加密

| 脚本 | 能力说明 |
|---|---|
| [javaCrypto.js](javaCrypto.js) | 加密算法自吐：hook `KeyGenerator`/`SecretKeySpec`/`MessageDigest`/`Signature`/`Cipher` 等，输出密钥、IV、明文、密文 |

### 脱壳与 dump

| 脚本 | 能力说明 |
|---|---|
| [shucking.js](shucking.js) | 简易脱壳：hook `libart.so` 的 `ClassLinker::LoadMethod`，读取 `DexFile` 基址与大小导出 dex |
| [dexDumper.py](dexDumper.py) | 运行时 DEX dump：hook `libdexfile.so` 的 `OpenCommon` 与 `libart.so` 的 `RegisterDexFile`/`LoadMethod`，`send` 给 Python 宿主按校验和去重保存 |
| [soDumper.py](soDumper.py) | so dump（脱壳）：以 `android_dlopen_ext`/`JNI_OnLoad` 为时机，`base.readByteArray(size)` 整段 dump 后用 SoFixer 修复 |

### 工具与 RPC

| 脚本 | 能力说明 |
|---|---|
| [rpc.py](rpc.py) | RPC 基础：JS 端 `rpc.exports` 暴露 Java 静态方法，Python 端调用 |
| [rpc2server.py](rpc2server.py) | RPC 暴露为 HTTP 服务：FastAPI 封装 Frida 导出方法，实现远程调用逆向接口 |
| [soInitInfo.js](soInitInfo.js) | 获取 so 文件 init 信息（init_proc/init_array 时机与地址） |

