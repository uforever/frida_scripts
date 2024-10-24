import os
import sys
import glob
import frida

package_name = ""

def on_message(message, data):
  if message['type'] == 'send':
    if package_name == "":
      return
    dex_file_name = f"{message['payload']}.dex"
    dex_file_path = os.path.join(os.getcwd(), package_name, dex_file_name)
    with open(dex_file_path, "wb") as f:
      f.write(data)


jscode = """
function main() {
  const libart = Module.enumerateSymbols("libart.so");
  const dexFileSizeSet = new Set();
  for (const item of libart) {
    if (item.name.includes("LoadMethod")) {
      console.log(JSON.stringify(item));
      const targetFuncAddr = item.address;
      Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
          const dexFilePtr = ptr(args[1]);
          const pointerSize = Process.pointerSize;
          const base = dexFilePtr.add(pointerSize).readPointer();
          const size = dexFilePtr.add(pointerSize * 2).readUInt();
          if (!dexFileSizeSet.has(size)) {
            dexFileSizeSet.add(size);
            console.log(`[Dump DexFile] base: ${base}, length: ${size}.`)
            const data = base.readByteArray(size);
            send(size, data);
          }
        },
      });
    }
  }
}

setImmediate(main);
"""

# usage: python dexDumper.py com.example.app
if __name__ == '__main__':
  try:
    package_name = sys.argv[1]
  except IndexError:
    print("Usage: python dexDumper.py package_name")
    sys.exit(1)

  # 查看当前目录下是否有package_name文件夹，如果没有则创建
  # 如果有则清空文件夹
  if os.path.exists(package_name):
    dex_files = glob.glob(os.path.join(package_name, '*.dex'))
    for dex_file in dex_files:
      os.remove(dex_file)
  else:
    os.makedirs(package_name)    

  device = frida.get_usb_device()
  pid = device.spawn(package_name)
  process = device.attach(pid)

  script = process.create_script(jscode)
  script.on('message', on_message)
  print('[*] Running DexDumper')
  script.load()

  device.resume(pid)
  sys.stdin.read()
