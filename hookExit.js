const libc = Process.getModuleByName('libc.so');

// abort 拦截：有些 Android 图形线程会在 libhwui.so 里触发 abort，
// 这类异常通常是渲染线程的“噪音”，不是业务代码真正崩溃；
// 所以我们先判断栈是不是来自 libhwui，如果是就挂起该线程，避免被误判为进程退出。
Interceptor.attach(libc.getExportByName('abort'), {
	onEnter() {
		// Thread.backtrace() 能拿到 abort 发生时的调用栈，用来区分“系统渲染线程”与“业务崩溃”。
		const bt = Thread.backtrace(this.context);
		let fromHwui = false;
		for (let i = 0; i < bt.length; i++) {
			const mod = Process.findModuleByAddress(bt[i]);
			// libhwui.so 属于 Android 视图渲染栈，渲染线程中的 abort 往往不是 app 自身退出条件。
			if (mod !== null && mod.name === 'libhwui.so') {
				fromHwui = true;
				break;
			}
		}
		if (fromHwui) {
			console.log('SUPPRESS abort from libhwui RenderThread');
			Thread.sleep(999999);
		} else {
			console.log('=== abort() ===');
			console.log(bt.map(DebugSymbol.fromAddress).join('\n'));
		}
	}
});

// 监控所有退出方式
['exit', '_exit', 'exit_group'].forEach(function (name) {
	const addr = libc.findExportByName(name);
	if (addr === null) return;
	Interceptor.attach(addr, {
		onEnter(args) {
			console.log('=== ' + name + '(' + args[0] + ') ===');
			console.log(Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n'));
		}
	});
});

// kill() 常被反调试、JNI 退出逻辑或自杀代码用到；
// 这里筛掉无关信号，只看“发给当前进程 / 进程组 / 典型终止信号”的情况，
// 目的是抓到真正导致进程退出、崩溃或被迫中止的调用链。
Interceptor.attach(libc.getExportByName('kill'), {
	onEnter(args) {
		const pid = args[0].toInt32();
		const sig = args[1].toInt32();
		if (pid === Process.id || pid === 0 || sig === 6 || sig === 9) {
			console.log('=== kill(pid=' + pid + ', sig=' + sig + ') ===');
			console.log(Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n'));
		}
	}
});

// tgkill() 是“按线程”发信号的接口，很多崩溃、反调试和线程退出逻辑会走这里；
// SIGABRT(6) / SIGKILL(9) / SIGSEGV(11) 是最典型的强制中止信号，
// 所以只打印这几类信号，能明显减少噪声并定位到崩溃来源。
const tgkillAddr = libc.findExportByName('tgkill');
if (tgkillAddr !== null) {
	Interceptor.attach(tgkillAddr, {
		onEnter(args) {
			const sig = args[2].toInt32();
			if (sig === 6 || sig === 9 || sig === 11) {
				console.log('=== tgkill(tgid=' + args[0] + ', tid=' + args[1] + ', sig=' + sig + ') ===');
				console.log(Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n'));
			}
		}
	});
}

// clone() 会在每次创建新线程时触发，
// 我们只关心“非 libart.so 自己启动的线程”，这样能发现被注入的原生线程和其他 ELF 模块创建的线程。
Interceptor.attach(libc.getExportByName('clone'), {
	onEnter(args) {
		if (args[3] != 0) {
			const startRoutine = args[3].add(96).readPointer();
			const module = Process.findModuleByAddress(startRoutine);
			if (module) {
				const moduleName = module.name;
				if (moduleName === 'libart.so') return;
				const moduleBase = module.base;
				const offset = startRoutine.sub(moduleBase);
				console.log(`Thread start routine found: ${moduleName} + 0x${offset.toString(16)}`);
			}
		}
	}
});

// raise也监控 — signal handler内部可能走这个
const raiseAddr = libc.findExportByName('raise');
if (raiseAddr !== null) {
	Interceptor.attach(raiseAddr, {
		onEnter(args) {
			const sig = args[0].toInt32();
			console.log('=== raise(sig=' + sig + ') ===');
			console.log(Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n'));
		}
	});
}

console.log('all libc probe installed');