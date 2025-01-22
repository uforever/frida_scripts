
const PKG_NAME = "com.example"; // 需要修改这里

let moduleBase = null;

let currentLevel = -1;

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
            if (moduleBase == null) {
              moduleBase = module.base;
              hookNative();
            }
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

  Java.perform(doJavaHook);

  // hookNative(); // 稍后手动执行
}


function doJavaHook() {
  let HelloJni = Java.use("com.example.hellojni.HelloJni");
  HelloJni["sign1"].implementation = function (str) {
    console.log(`HelloJni.sign1 is called: str=${str}`);
    let result = this["sign1"](str);
    console.log(`HelloJni.sign1 result=${result}`);
    return result;
  };

  HelloJni["sign2"].implementation = function (str, str2) {
    console.log(`HelloJni.sign2 is called: str=${str}, str2=${str2}`);
    let result = this["sign2"](str, str2);
    console.log(`HelloJni.sign2 result=${result}`);
    return result;
  };
}




function printHex(addr) {
  console.log(hexdump(moduleBase.add(addr), {
    offset: 0,
    length: 64,
    header: true,
    ansi: true
  }));
}


function hookNative() {

  Interceptor.attach(moduleBase.add(0x1531C), {
    onEnter: function (args) {
      currentLevel += 1;
      this.arg0 = args[0];
      this.arg1 = args[1];
      this.arg2 = args[2];
      console.log("\t".repeat(currentLevel) + "[*] sub_1531C onEnter");
      console.log(`- arg0: ${hexdump(this.arg0, { length: 0x30 })}`);
      console.log(`- arg1: ${hexdump(this.arg1, { length: 0x30 })}`);
      // console.log(`- arg2: ${hexdump(this.arg2, { length: 0x30 })}`);
    },
    onLeave: function (_retval) {
      console.log("\t".repeat(currentLevel) + "[*] sub_1531C onLeave");
      console.log(`- arg0: ${hexdump(this.arg0, { length: 0x30 })}`);
      console.log(`- arg1: ${hexdump(this.arg1, { length: 0x30 })}`);
      // console.log(`- arg2: ${hexdump(this.arg2, { length: 0x30 })}`);
      currentLevel -= 1;
    }
  });


  Interceptor.attach(moduleBase.add(0x12CF4), {
    onEnter: function (args) {
      currentLevel += 1;
      this.arg0 = args[0];
      this.arg1 = args[1];
      this.arg2 = args[2];
      console.log("\t".repeat(currentLevel) + "[*] sub_12CF4 onEnter");
      console.log(`- arg0: ${hexdump(this.arg0, { length: 0x30 })}`);
      // console.log(`- arg1: ${hexdump(this.arg1, { length: 0x30 })}`);
      // console.log(`- arg2: ${hexdump(this.arg2, { length: 0x30 })}`);
    },
    onLeave: function (_retval) {
      console.log("\t".repeat(currentLevel) + "[*] sub_12CF4 onLeave");
      console.log(`- arg0: ${hexdump(this.arg0, { length: 0x30 })}`);
      // console.log(`- arg1: ${hexdump(this.arg1, { length: 0x30 })}`);
      // console.log(`- arg2: ${hexdump(this.arg2, { length: 0x30 })}`);
      currentLevel -= 1;
    }
  });


  Interceptor.attach(moduleBase.add(0x18AB0), {
    onEnter: function (args) {
      currentLevel += 1;
      this.arg0 = args[0];
      this.arg1 = args[1];
      this.arg2 = args[2];
      console.log("\t".repeat(currentLevel) + "[*] sub_18AB0 onEnter");
      console.log(`- arg0: ${hexdump(this.arg0, { length: 0x30 })}`);
      console.log(`- arg1: ${hexdump(this.arg1, { length: 0x30 })}`);
      console.log(`- arg2: ${hexdump(this.arg2, { length: 0x30 })}`);
    },
    onLeave: function (_retval) {
      console.log("\t".repeat(currentLevel) + "[*] sub_18AB0 onLeave");
      console.log(`- arg0: ${hexdump(this.arg0, { length: 0x30 })}`);
      console.log(`- arg1: ${hexdump(this.arg1, { length: 0x30 })}`);
      console.log(`- arg2: ${hexdump(this.arg2, { length: 0x30 })}`);
      currentLevel -= 1;
    }
  });

}

// printHex(0x37040);

setImmediate(main);
