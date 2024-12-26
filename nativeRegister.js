const PKG_NAME = "com.example.demo"; // 需要修改这里

const STD_STRING_SIZE = 3 * Process.pointerSize;
class StdString {
  constructor() {
    this.handle = Memory.alloc(STD_STRING_SIZE);
  }

  dispose() {
    const [data, isTiny] = this._getData();
    if (!isTiny) {
      Java.api.$delete(data);
    }
  }

  disposeToString() {
    const result = this.toString();
    this.dispose();
    return result;
  }

  toString() {
    const [data] = this._getData();
    return data.readUtf8String();
  }

  _getData() {
    const str = this.handle;
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
    return [data, isTiny];
  }
}

function prettyMethod(method_id, withSignature) {
  const result = new StdString();
  Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
  return result.disposeToString();
}

function main() {
  const libart = Module.enumerateExports("libart.so");

  for (const export_func of libart) {
    if (export_func.name.includes("RegisterNativeMethod")) {
      console.log(`
[+] hook Native Function
- module: libart.so
- function: RegisterNativeMethod`);
      Interceptor.attach(export_func.address, {
        onEnter: function (args) {
          const methodName = prettyMethod(args[1], true);
          const retvalType = methodName.split(' ')[0];
          if (methodName.includes(PKG_NAME)) {
            const module = Process.findModuleByAddress(args[2]);
            const offset = args[2].sub(module.base);
            console.log(`
[!] RegisterNativeMethod
- method: ${methodName}
- module: ${module.name}
- offset: ${offset}`);
            Interceptor.attach(args[2], {
              onLeave: function (retval) {
                if (retvalType === 'int') {
                  console.log(`
[*] Leave NativeMethod ${methodName}
- retval: ${retval}`);
                } else if (retvalType === 'java.lang.String') {
                  console.log(`
[*] Leave NativeMethod ${methodName}
- retval: ${Java.cast(retval, Java.use('java.lang.String'))}`);
                }
              },
            });
          }
        },
      });
    }
  }
}

setImmediate(main);
