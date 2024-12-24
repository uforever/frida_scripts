// 添加一些不需要hook的so
const soNameSet = new Set([
  "libandroid.so",
  "liblog.so",
  "libm.so",
  "libdl.so",
  "libc.so",
  "libEGL.so",
  "javalib.odex",
  "system@priv-app@RtMiCloudSDK@RtMiCloudSDK.apk@classes.dex",
]);

function hookSoInit() {
  // /system/bin/linker64
  const linker = (Process.pointerSize == 8) ?
    Process.findModuleByName("linker64") : Process.findModuleByName("linker");
  if (linker) {
    const symbols = linker.enumerateSymbols();
    // void soinfo::call_constructors()
    for (const symbol of symbols) {
      if (symbol.name.includes("call_constructors")) {

        console.log(`
[+] hook Native Function
- module: linker
- function: call_constructors`);

        Interceptor.attach(symbol.address, {
          onEnter: function (args) {
            const soinfo = args[0];
            const soName = soinfo.add(408).readPointer().readCString();

            if (!soNameSet.has(soName)) {
              soNameSet.add(soName);
              const module = Process.findModuleByName(soName);
              if (module) {
                const base = module.base;
                const initProc = soinfo.add(184).readPointer();
                const initArray = soinfo.add(152).readPointer();
                const initArrayCount = soinfo.add(160).readU64();

                const initArrayFuncs = Array.from({ length: initArrayCount }, (_, index) =>
                  initArray.add(Process.pointerSize * index).readPointer().sub(base)
                );

                console.log(`
[*] call_constructors onEnter
- so_name: ${soName}
- init_proc: ${(initProc == 0x0) ? "null" : initProc.sub(base)}
- init_array: ${(initArray == 0x0) ? "null" : initArray.sub(base)}
- init_array_count: ${initArrayCount}
  ${initArrayFuncs.join(', ')}`);
              }
            }
          }
        });
      }
    }
  }
}

setImmediate(hookSoInit);
