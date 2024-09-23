const targetLib = "libcrackme.so";

function main() {
  // hook pthread_create函数 其第三个参数为函数指针
  Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
      const pthreadFunc = args[2];
      try {
        const module = Process.getModuleByAddress(pthreadFunc);
        if (module.name === targetLib) {
          console.log("pthread create by target lib, func addr: ", pthreadFunc);
          // 替换反调试函数
          Interceptor.replace(pthreadFunc, new NativeCallback(function() {
            console.log("bypass anti-debug function");
            return 0;
          }, 'int', []));
        }
      } catch (_e) {
      }
    },
  });
}

setImmediate(main);
