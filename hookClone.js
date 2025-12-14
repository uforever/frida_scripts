/*
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine) (void *), void *arg);
pthread_create 函数第三个参数是线程函数地址

IDA分析start_routine参数传递到clone函数的过程
__int64 __fastcall pthread_create(_QWORD *a1, __int128 *a2, __int64 a3, __int64 a4)
也就是这里的a3参数

*(_QWORD *)(v30 + 96) = a3;
…………
v32 = clone(__pthread_start, v18, 4001536LL, v30, v30 + 16, v22 + 8, v30 + 16);

这里v30对应的应该是描述子线程的结构体
其加96偏移存储的就是线程函数地址a3
通过读取第四个参数 + 96 的地址，我们可以获取实际执行的线程函数
*/

function hookClone() {
  const cloneFunc = Module.findExportByName(null, "clone");
  if (!cloneFunc) {
    console.log("clone function not found");
    return;
  }
  Interceptor.attach(cloneFunc, {
    onEnter(args) {
      if (args[3] != 0) {
        const startRoutine = args[3].add(96).readPointer();
        const module = Process.findModuleByAddress(startRoutine);
        if (module) {
          const moduleName = module.name;
          const moduleBase = module.base;
          const offset = startRoutine.sub(moduleBase);
          console.log(`Thread start routine found: ${moduleName} + 0x${offset.toString(16)}`);
        }
      }
    },
    onLeave(retval) {
      // do nothing
    }
  });
}

function main() {
  hookClone();
}

setImmediate(main);
