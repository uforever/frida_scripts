const mainModule = Process.mainModule;
const appStart = mainModule.base;
const appEnd = appStart.add(mainModule.size);
const x64 = Process.pointerSize == 8;

function formattedAddress(address) {
  const l = x64 ? 16 : 8;
  return `${address}`.substring(2).padStart(l, '0');
}

const mainThread = Process.enumerateThreads()[0];
Stalker.follow(mainThread.id, {
  transform(iterator) {
    let instruction = iterator.next();

    const startAddress = instruction.address;
    const isAppCode = startAddress.compare(appStart) >= 0 &&
      startAddress.compare(appEnd) === -1;

    const canEmitNoisyCode = iterator.memoryAccess === 'open';

    do {
      if (isAppCode && canEmitNoisyCode) {
        const insAddress = instruction.address;
        const byteArray = insAddress.readByteArray(instruction.size);
        const uint8Array = new Uint8Array(byteArray);
        const byteCode = Array.from(uint8Array).map(byte => ('0' + byte.toString(16)).slice(-2)).join(' ').padEnd(44, ' ');
        const mnemonic = instruction.mnemonic;
        const opStr = instruction.opStr;
        const disassemble = `${mnemonic} ${opStr}`.padEnd(50, ' ');


        const onMatch = (context) => {
          // console.log(JSON.stringify(context));
          const registers = x64
            ? [
              "rax", "rbx", "rcx", "rdx",
              "rsi", "rdi", "rbp", "rsp",
              "r8", "r9", "r10", "r11",
              "r12", "r13", "r14", "r15",
              // "rflags" // frida 尚不支持
            ]
            : [
              "eax", "ebx", "ecx", "edx",
              "esi", "edi", "ebp", "esp",
              // "eflags" // frida 尚不支持
            ];

          const regStr = registers.map(r => `${r}: ${formattedAddress(context[r])}`).join(' ');
          console.log(`${insAddress} | ${byteCode} | ${disassemble} | ${regStr}`);
        };
        iterator.putCallout(onMatch);
      }
      iterator.keep();
    } while ((instruction = iterator.next()) !== null);
  },
});
