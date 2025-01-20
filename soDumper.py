import sys
import time
import frida

package_name = ""
so_name = ""

def js_script(so_name):
  return f'const targetLib = "{so_name}";' + """
function soDump(soName) {
  const module = Process.findModuleByName(soName);
  const size = module.size;
  const base = module.base;
  Memory.protect(base, size, 'rwx');
  send({ name: soName, base: base, size: size }, Memory.readByteArray(base, size));
}

function libdlHook() {
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

        if (this.filename.includes(targetLib)) this.isTarget = true;
      }
    },
    onLeave: function () {
      if (this.isTarget) soDump(targetLib);
    },
  });
}

setImmediate(libdlHook);
"""

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


# usage: python soDumper.py com.example.app libnative-lib.so
if __name__ == '__main__':
    try:
        package_name = sys.argv[1]
        so_name = sys.argv[2]
    except IndexError:
        print("Usage: python soDumper.py <package_name> <so_name>")
        sys.exit(1)

    # ./server -l 0.0.0.0:24486
    # adb forward tcp:24486 tcp:24486
    device = frida.get_device_manager().add_remote_device("127.0.0.1:24486")
    pid = device.spawn([package_name])
    process = device.attach(pid)
    script = process.create_script(js_script(so_name))
    script.on('message', on_message)
    script.load()

    time.sleep(2)
    device.resume(pid)
    sys.stdin.read()

""" 输出示例
[*] Dump so File
- name: libDexHelper.so
- base: 0x70c8db0000
- size: 1089536
[+] Dumped Successfully
"""

""" 修复
SoFixer -s libInput.so -o libOutput.so -m 0x70c8db0000
"""
