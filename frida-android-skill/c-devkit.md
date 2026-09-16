# C 层开发：frida-core / gum / gumjs devkit

涉及 Native 级注入、跨进程控制或需要核对 `frida-core.h`、`frida-gum.h`、`frida-gumjs.h` 时使用本章。

## 1. 三层定位

| 头文件 | 定位 | Android 常见场景 | 代表接口 |
|---|---|---|---|
| `frida-core.h` | 设备与会话控制层 | `spawn/attach/resume`、创建脚本、与 App 进程通信 | `frida_device_manager_new`、`frida_device_spawn_sync`、`frida_device_attach_sync`、`frida_session_create_script_sync` |
| `frida-gum.h` | 进程内插桩底座 | InlineHook、内存读写扫描、模块符号解析、线程跟踪 | `gum_interceptor_attach`、`gum_memory_scan`、`gum_process_enumerate_modules`、`gum_stalker_follow_me` |
| `frida-gumjs.h` | Gum 与 JS 运行时桥接层 | 在目标进程内加载 JS 脚本并收发消息 | `gum_script_backend_obtain_qjs`、`gum_script_backend_create_sync`、`gum_script_load_sync` |

推荐链路：`DeviceManager -> Device -> Session -> Script(core)`，再到 `ScriptBackend/Script(gumjs)`，最后调用 `Interceptor/Memory/Stalker(gum)` 能力。

## 2. ABI 映射

```bash
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
	arm64-v8a|arm64|aarch64) FRIDA_ARCH="arm64"; TARGET_TRIPLE="aarch64-linux-android" ;;
	armeabi-v7a|arm|armv7l) FRIDA_ARCH="arm"; TARGET_TRIPLE="armv7a-linux-androideabi" ;;
	x86_64|amd64) FRIDA_ARCH="x86_64"; TARGET_TRIPLE="x86_64-linux-android" ;;
	x86|i686) FRIDA_ARCH="x86"; TARGET_TRIPLE="i686-linux-android" ;;
	*) echo "Unsupported ABI: $ABI" >&2; exit 1 ;;
esac
```

## 3. devkit 下载

```bash
FRIDA_VERSION="${FRIDA_VERSION:-17.10.1}"
mkdir -p downloads toolchains/devkits
curl -fsSL "https://api.github.com/repos/frida/frida/releases/tags/${FRIDA_VERSION}" -o "downloads/release.json"

for ASSET in \
	"frida-core-devkit-${FRIDA_VERSION}-android-${FRIDA_ARCH}.tar.xz" \
	"frida-gum-devkit-${FRIDA_VERSION}-android-${FRIDA_ARCH}.tar.xz" \
	"frida-gumjs-devkit-${FRIDA_VERSION}-android-${FRIDA_ARCH}.tar.xz"
do
	URL="$(jq -r --arg name "$ASSET" '.assets[] | select(.name == $name) | .browser_download_url' downloads/release.json | head -n 1)"
	curl -fL "$URL" -o "downloads/$ASSET"
done
```

版本核对：

```bash
curl -fsSL https://api.github.com/repos/frida/frida/releases/latest | jq -r '.tag_name,.published_at'
```

## 4. NDK 编译模板

core 样例：

```bash
API_LEVEL="${API_LEVEL:-24}"
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host-tag>/bin/${TARGET_TRIPLE}${API_LEVEL}-clang"

"$CC" -DANDROID -ffunction-sections -fdata-sections \
	-Itoolchains/devkits/frida-core-devkit \
	examples/c/frida-core-sample.c \
	-o build/frida-core-sample \
	-Ltoolchains/devkits/frida-core-devkit -lfrida-core -llog -ldl -lm -pthread -Wl,--export-dynamic
```

gum 样例链接 `-lfrida-gum`；gumjs 样例通常使用 `clang++` 并链接 `-lfrida-gumjs`。

## 5. 设备侧运行

```bash
REMOTE_DIR="/data/local/tmp/frida-android-api"
adb shell "mkdir -p '$REMOTE_DIR'"
adb push build/frida-core-sample "$REMOTE_DIR/frida-core-sample"
adb shell "chmod 755 '$REMOTE_DIR/frida-core-sample'"
adb shell "'$REMOTE_DIR/frida-core-sample' <target-pid>"
```

## 6. 核心接口速查

frida-core 样例组织顺序：

- `frida_init`、`frida_version`、`frida_version_string`
- `frida_device_manager_new`、`frida_device_manager_enumerate_devices_sync`
- `frida_device_query_system_parameters_sync`、`frida_device_enumerate_applications_sync`、`frida_device_enumerate_processes_sync`
- `frida_device_spawn_sync` 或 `frida_device_attach_sync` 进入 Session
- `frida_session_create_script_sync` 或 `frida_session_compile_script_sync + frida_session_create_script_from_bytes_sync`
- `frida_script_load_sync`、`frida_script_post`、`frida_script_unload_sync`
- `frida_session_detach_sync`、`frida_device_manager_close_sync`

frida-gum 样例组织顺序：

- `gum_init_embedded`
- `gum_process_enumerate_threads`、`gum_process_enumerate_modules`
- `gum_module_enumerate_imports`、`gum_module_enumerate_exports`、`gum_symbol_details_from_address`
- `gum_memory_scan`、`gum_memory_read`、`gum_memory_write`
- `gum_interceptor_obtain`、`gum_interceptor_attach`、`gum_interceptor_replace`
- `gum_stalker_new`、`gum_stalker_follow_me`、`gum_stalker_add_call_probe`
- `gum_deinit_embedded`

frida-gumjs 样例组织顺序：

- `gum_init_embedded`
- `gum_script_backend_obtain_qjs` 或 `gum_script_backend_obtain`
- `gum_script_backend_create_sync`、`gum_script_set_message_handler`
- `gum_script_load_sync`、`gum_script_post`、`gum_script_unload_sync`
- `gum_script_backend_compile_sync`、`gum_script_backend_create_from_bytes_sync`、`gum_script_backend_snapshot_sync`
- `gum_script_backend_get_scheduler`、`gum_script_scheduler_push_job_on_js_thread`
- `gum_deinit_embedded`

## 7. Python 绑定速查（宿主控制平面）

```python
# 设备与生命周期
device = frida.get_usb_device() / frida.get_remote_device()
device = frida.get_device_manager().add_remote_device("127.0.0.1:<port>")
pid = device.spawn([package]); device.resume(pid)
session = device.attach(pid); session.detach()

# 脚本
script = session.create_script(source)   # 或 create_script_from_bytes
script.on("message", on_message)         # message: {'type': 'send'|'error', ...}
script.load(); script.unload()
script.post(message)                     # 宿主 → JS
script.exports_sync.func(...)            # 同步 RPC（func 为 rpc.exports 中的导出名）
script.exports_async.func(...)           # 异步 RPC
script.list_exports_sync()               # 检查导出名

# 常见异常
frida.ServerNotRunningError   # server 未启动
frida.TransportError          # 连接/传输问题
frida.ProcessNotFoundError    # 进程名/ID 不对
frida.PermissionDeniedError   # 权限不足（root/SELinux）
frida.TimedOutError
```

JS 端接收宿主消息：

```javascript
recv('payload', function (message) {
    console.log('from host: ' + JSON.stringify(message));
});
```
