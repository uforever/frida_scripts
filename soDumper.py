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
      if (this.isTarget) {
        const filename = this.filename;
        const jniOnload = Module.findExportByName(filename, "JNI_OnLoad");
        if (jniOnload) {
          Interceptor.attach(jniOnload, {
            onEnter: function (_args) {
              // 判断反调试是否在初始化时已经执行
              // 还是在JNI_OnLoad之中执行
              console.log(`
[*] ${filename} JNI_OnLoad onEnter`);
              soDump(targetLib);
            },
            onLeave: function () {
              if (Java.available) {
                // Java.perform(doJavaHook);
              }
            },
          });
        }
      }
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

    device = frida.get_device_manager().add_remote_device("127.0.0.1:24486")
    pid = device.spawn([package_name])
    process = device.attach(pid)
    script = process.create_script(js_script(so_name))
    script.on('message', on_message)
    script.load()

    time.sleep(2)
    device.resume(pid)
    sys.stdin.read()
