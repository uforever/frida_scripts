---
name: frida-android-skill
description: Android Frida dynamic analysis. Invoke for Java/Native hooks, anti-Frida/SSL-pinning bypass, DEX/SO dumping, Stalker tracing, algorithm tracing, or adb/frida-server environment troubleshooting.
---

# Frida 安卓动态分析技能

面向 Android 平台的 Frida 动态分析与逆向工程全链路技能。覆盖环境准备与故障排查、Frida 17 新版 API 规范、Java/Native 层 Hook、时机注入、反检测绕过、SSL unpinning、算法自吐、DEX/SO dump、流量抓取与 Stalker 跟踪。本技能独立使用，所有代码片段完整内联。

## 文件导航

| 文件 | 内容 | 何时读 |
|---|---|---|
| `environment.md` | 虚拟环境、adb、root、frida-server（含魔改版确认）、连接失败排查 | **每次动手前必读** |
| `api-conventions.md` | Frida 17 API 硬性约定、16.x 版本兼容陷阱、Process/Module/Memory/Interceptor/Stalker/Cloak 完整规范 | 生成或修改任何脚本前 |
| `templates-java.md` | Java 层模板：基础 hook、壳内 hook、批量追踪、算法自吐、UI 事件、RPC | Java 层任务 |
| `templates-native.md` | Native 层模板：时机 hook、JNI 注册监控、参数/返回值篡改、主动调用、patchCode、Stalker | Native 层任务 |
| `anti-detection.md` | 反检测四步定位法、libc 绕过全套、dlsym 拦截、inline svc、**延迟毒化识别与处理（§14 实战复盘）**、Zygisk、定向绕过骨架 | 目标有反调试/安全 SDK 时 |
| `network-tls.md` | SSL unpinning 多框架、客户端证书导出、socket/SSL 明文抓取 | 网络与证书任务 |
| `unpack-dump.md` | DEX 脱壳、SO dump、隐藏 so 定位 | 脱壳/dump 任务 |
| `c-devkit.md` | frida-core/gum/gumjs devkit 下载与 NDK 编译命令 | C 层开发任务 |

## 执行原则

1. **环境先行**：动手前按 `environment.md` 完成环境确认，尤其要向用户确认魔改 frida 的名称与端口，不要假设默认值。
2. **先观测后改写**：先打印证据（模块、偏移、调用栈、输入输出），确认 Hook 点后再替换。无法确认的点只打印，不盲目 hook。
3. **反检测优先安装**：所有反检测 Hook（`dlopen`、`android_dlopen_ext`、`dlsym`、`pthread_create`、`/proc` 过滤）必须在 `Java.perform()` 之前安装。反检测脚本不混入业务 Hook。
4. **Frida 17 API**：禁止使用已移除的旧式静态 API（`Module.findExportByName(null, name)` 等），规范见 `api-conventions.md`。
5. **二进制数据走宿主**：dump 数据用 `send(message, data)` 交给 Python 宿主保存，避免 App 内写文件权限问题。
6. **最小改动**：对系统关键函数只做最小改动，改写前保存原函数引用以便恢复，长时跟踪设置明确停止条件。

## 场景速查

| 需求 | 模板位置 |
|---|---|
| Java 方法 hook、字段、构造、内部类 | `templates-java.md` §1-2 |
| 加固壳内定位业务类 | `templates-java.md` §3 |
| 批量方法追踪（调用链分析） | `templates-java.md` §4 |
| 加密算法自吐（密钥/IV/明文密文） | `templates-java.md` §5 |
| UI 点击事件监控 / 启动指定 Activity | `templates-java.md` §6-7 |
| RPC 导出 + Python 宿主 / HTTP 服务 | `templates-java.md` §8 |
| so 加载时机 hook（dlopen/JNI_OnLoad/init_array） | `templates-native.md` §1-2 |
| JNI 动态注册监控 | `templates-native.md` §3 |
| native 返回值修改 / 参数篡改 / 主动调用 | `templates-native.md` §4-6 |
| 内存读写 / hook clone / patchCode | `templates-native.md` §7-9 |
| Stalker 指令跟踪 | `templates-native.md` §10 |
| 反调试绕过（阿里 SDK、通用 Frida 检测） | `anti-detection.md` 全文 |
| Root / VPN / 模拟器 EGL 检测处理 | `anti-detection.md` §8-10 |
| SSL unpinning（OkHttp/Conscrypt/多框架） | `network-tls.md` §1-2 |
| 客户端证书导出（双向 TLS） | `network-tls.md` §3 |
| SSL/TCP/UDP 明文抓取 | `network-tls.md` §4 |
| DEX 脱壳 dump | `unpack-dump.md` §1-2 |
| 加固壳 arm32 脱壳（爱加密成功样本、产物校验） | `unpack-dump.md` §5 |
| SO dump / 隐藏 so 定位 | `unpack-dump.md` §3-4 |
| 延迟毒化（固定 SIGSEGV）/ Stalker 反噬 / arm32 svc 差异 | `anti-detection.md` §14 |
| C 层 devkit 编译 | `c-devkit.md` |

## 生成脚本的标准流程

1. 明确目标：包名、进程名、ABI、Android 版本、Frida 版本、启动方式（spawn/attach）、目标类或目标 so。
2. 产出观测脚本：打印 `Frida.version`、`Process.arch`、`Process.pointerSize`、模块列表、符号、调用栈、关键输入输出。
3. 根据证据生成改写脚本：只改已确认 Hook 点，保留原函数调用或明确的撤销方式。
4. 宿主脚本负责生命周期：`spawn -> attach -> create_script -> on_message -> load -> resume -> RPC/观察 -> detach`。
5. 交付时同时给出：运行命令（如 `frida -U -f <package> -l agent.js` 或 `python host.py`）、预期日志样例、失败时下一步证据采集命令、改写点与撤销方式。

## 排查规则摘要

- Native hook 不触发：先确认模块已加载（`Process.findModuleByName`）、符号已导出（`module.enumerateExports()` / `ApiResolver('module')`）、是否 C++ mangle（用 `exports:*!*func*` 模糊匹配）。
- Java 方法 hook 失败：先打印 `method.overloads` 的 `argumentTypes` 再写精确签名；业务类找不到多半是壳换了 ClassLoader。
- `rpc.exports` 不可见：确认 `script.load()` 已完成，用 `script.list_exports_sync()` 检查。
- spawn 即死（无任何 hook 日志）：大概率反调试，按 `anti-detection.md` 四步定位法处理，不要继续堆 hook。
- 进程死但无任何 exit/kill 链触发：先查 logcat 死法——**多次运行 fault addr 完全相同的 SIGSEGV = 壳的延迟毒化**，此时优先做减法（移除 Stalker 等干扰源，确认 TracerPid 是否本来就是 0），而不是堆绕过，详见 `anti-detection.md` §14。
- 堆绕过后死亡时间点提前或死亡形态不变：你的绕过本身就是干扰源（典型：对自修改壳用 Stalker），回退到最小干预路线。
- 客户端/设备端为 Frida 16.x 时 `Module.findGlobalExportByName` 等 17 API 不存在（TypeError），按 `api-conventions.md` 的版本兼容写法适配。
- 接口报错：先核对 Frida 版本与官方文档 https://frida.re/docs/javascript-api/ ，17.x 已移除大量 Module/Memory 静态 API。
