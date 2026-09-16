# 环境准备与故障排查

**每次动手前必须完成本章确认。任何一项不确定时，先向用户提问，不要假设默认值。**

## 1. Python 与 Frida 工具环境

- 用户的相关工具（frida、frida-tools、Python 包）**可能安装在虚拟环境中**（venv / conda / pipx）。不要在当前环境直接 `pip install frida-tools` 重新安装，先向用户确认：
  - 使用哪个 Python / 虚拟环境（如 `conda activate xxx` 或 `.venv/Scripts/python`）
  - frida / frida-tools 的安装位置与调用方式
- 版本校验（**客户端与设备端版本最好一致**，大版本不匹配是最常见的连接失败原因）：

```bash
frida --version
python -c "import frida; print(frida.__version__)"
# 设备端版本，路径以实际为准（魔改版可能不在默认位置，见下节）
adb shell "/data/local/tmp/frida-server --version"
```

## 2. adb 连接与权限

```bash
adb devices                                    # 确认设备已连接且状态为 device（不是 offline/unauthorized）
adb shell getprop ro.build.version.release     # Android 版本
adb shell getprop ro.product.cpu.abi           # ABI：arm64-v8a 决定 frida-server 用 arm64 版
```

- root 方式需向用户确认，两种常见情况：
  - 官方模拟器 / userdebug 固件：`adb root` 后 adb shell 即为 root
  - 真机 Magisk / KernelSU：需 `adb shell` 后 `su` 提权
- 执行需要 root 的操作前先验证：

```bash
adb shell "su -c id"    # 输出 uid=0(root) 才算 root 成功
adb shell id            # userdebug 固件可直接输出 uid=0
```

## 3. frida-server 检查（含魔改版确认清单）

**⚠️ 用户可能使用魔改版 frida-server**（改名为随机名、改默认端口、去除特征字符串以对抗检测）。以下事项必须逐项向用户确认或自行探测，不要假设默认值：

| 确认项 | 默认值 | 说明 |
|---|---|---|
| server 二进制名称 | `frida-server` | 魔改后可能是任意名称（如 `fs`、`hluda`、随机串），询问或 `ls` 搜索 |
| server 在设备上的路径 | `/data/local/tmp/` | 魔改版可能藏在其他目录 |
| 监听端口 | `27042` | 魔改版通常改端口防扫描，连接时必须用 `-H 127.0.0.1:<port>` |
| 特征线程名 | `gmain`/`gdbus`/`gum-js-loop` | 魔改版可能已改名，影响反检测脚本中的关键字列表 |
| 客户端与 server 版本一致性 | 同版本 | 魔改版可能自定义版本号，以实际兼容为准 |
| 启动方式 | 用户手动 / adb shell | **由用户选择**，不要擅自启动 |

探测命令（名称未知时）：

```bash
# 查找可能的 frida-server（按特征搜索）
adb shell "su -c 'ls -l /data/local/tmp/'"
adb shell "su -c 'ps -A | grep -iE \"frida|gadget|server\"'"
# 确认是否已在运行、监听端口
adb shell "su -c 'netstat -tlnp | grep -v kernel'"
```

常规版启动命令（经用户确认后执行）：

```bash
adb shell "su -c '/data/local/tmp/frida-server &'"     # 常规启动
adb shell "su -c 'setenforce 0'"                       # SELinux 阻断时
adb forward tcp:27042 tcp:27042                        # 需要远程转发时（魔改端口同步替换）
```

## 4. 连接方式选择

```bash
# USB 直连（frida-server 默认端口）
frida-ps -U
frida -U -f <package> -l agent.js

# 魔改端口 / 远程设备：先 forward 再指定 -H
adb forward tcp:<port> tcp:<port>
frida -H 127.0.0.1:<port> -f <package> -l agent.js

# Python 宿主
device = frida.get_usb_device()                        # USB
device = frida.get_device_manager().add_remote_device("127.0.0.1:<port>")  # 魔改端口/远程
```

## 5. frida 连不上时的排查顺序

| 现象 | 原因 | 处理 |
|---|---|---|
| `Failed to enumerate processes: closed` / `server not running` | frida-server 未启动或已退出 | 按 §3 确认名称与路径后启动；`ps -A` 确认进程存在 |
| `unable to connect to remote device` / 超时 | 端口不对（魔改版）或设备离线 | 确认监听端口；`adb devices` 确认状态；`adb forward` 后用 `-H` |
| `unable to find process with name` | 进程名与实际不符 | `frida-ps -Ua`（应用）或 `frida-ps -U`（进程）确认 |
| 连上但 spawn 即崩、脚本不生效 | 客户端与 server 版本不匹配 | 统一升级或降级两侧到同一版本 |
| attach 后 App 秒退（无任何 hook 日志） | 目标有反调试（ptrace 检测） | 见 `anti-detection.md`，不要继续堆 hook |
| 模拟器上 server 起不来 | ABI 不对（x86 设备装了 arm64 版） | 按 `ro.product.cpu.abi` 换对应版本 |
| server 启动即被杀 | SELinux 强制模式 | `su -c 'setenforce 0'` 后重启 server |
| `-U` 找不到设备 | adb 未授权或 frida-server 未运行 | 先 `adb devices` 确认，再确认 server 存活 |

## 6. 运行模式选择

| 模式 | 命令 | 适用 |
|---|---|---|
| spawn（推荐） | `frida -U -f <package> -l agent.js` | 需要抢在目标 so 加载/反检测初始化之前安装 hook |
| attach | `frida -U -F -l agent.js` 或 `frida -U -n <pkg> -l agent.js` | 目标已运行、无严格时机要求 |
| V8 调试 | `exec frida --runtime=v8 --debug -D <serial> -f <package> -l agent.js` | 需要 Chrome DevTools 调试脚本（Inspector 端口 9229） |

反调试目标必须用 **spawn 模式**；检测线程在构造阶段启动的目标，还需要更早的 linker 级时机（见 `anti-detection.md` §6）。
