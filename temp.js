const targetLib = "libcrackme.so";

function main() {
  console.log("-------- Start Hooking --------");

  const adeAddr = Module.findExportByName(null, "android_dlopen_ext");
  Interceptor.attach(adeAddr, {
    onEnter: function(args) {
      const pathptr = args[0];
      this.isTarget = false;
      if (pathptr) {
        // 读取字符串写法2 两种方式都可以
        const path = ptr(pathptr).readCString();
        console.log("android_dlopen_ext called with: ", path);
        if (path.includes(targetLib)) {
          // 命中目标库 标记上
          this.isTarget = true;
        }
      }
    },
    onLeave: function() {
      // 如果是目标库
      if (this.isTarget) {
        const dylibAddr = Module.findBaseAddress(targetLib);
        // 返回值篡改
        Interceptor.replace(dylibAddr.add(0x16A4), new NativeCallback(function() {
          console.log("bypass anti-debug func")
          return 0;
        }, 'int', []));
      }
    }
  });
}

setImmediate(main);
