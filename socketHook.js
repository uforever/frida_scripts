// hook 开关
const hookSocket = false; // Java层 Socket构造hook
const hookTcp = false; // TCP hook开关 HTTP的话 开启这个就够了
const hookUdp = false;  // UDP hook开关
const hookConscrypt = false; // 暂时感觉用处不大
const hookSsl = true; // HTTPS hook开关 大部分场景只开这一个就够了
const useHexDump = false; // or UTF-8 plaintext
const traceStack = false; // 是否打印堆栈

function main() {
  doNativeHook();
  Java.perform(() => {
    doJavaHook(Java);
  });
}

function doNativeHook() {
  const resolver = new ApiResolver("module");

  const nativeBufOpFunc = function (buffer, length) {
    let result = "\n";
    if (length > 0) {
      if (useHexDump) {
        result += hexdump(buffer, {
          offset: 0,
          length: length,
          header: true,
          ansi: true
        });
      } else {
        // result += buffer.readUtf8String(length); // 这里可能会读到某些字节无法正确解码而报错
        result += buffer.readCString(length);
      }
    }
    return result;
  };

  if (hookSsl) {
    const sslModuleName = "*libssl*"; // "*libboringssl*" for iOS
    // const sslApiList = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id"];
    const sslApiList = ["SSL_read", "SSL_write"];
    const sslApiAddress = {};
    for (const sslApi of sslApiList) {
      const matches = resolver.enumerateMatchesSync(`exports:${sslModuleName}!${sslApi}`);
      if (matches.length == 0) {
        console.log(`[!] No matches for ${sslApi}`);
        continue;
      }
      if (matches.length > 1) {
        console.log(`[!] Multiple matches for ${sslApi}`);
        continue;
      }
      sslApiAddress[sslApi] = matches[0].address;
    }
    // int SSL_get_fd(SSL *ssl); // 获取与当前 SSL 会话关联的底层文件描述符（通常是套接字描述符）
    // const SSL_get_fd = new NativeFunction(sslApiAddress["SSL_get_fd"], "int", ["pointer"]);
    // SSL_SESSION *SSL_get_session(SSL *ssl); // 获取与当前 SSL 会话关联的 SSL 会话对象
    // const SSL_get_session = new NativeFunction(sslApiAddress["SSL_get_session"], "pointer", ["pointer"]);
    // uint8_t *SSL_SESSION_get_id(SSL_SESSION *session, unsigned int *out_len); // 获取指定 SSL 会话的会话 ID
    // const SSL_SESSION_get_id = new NativeFunction(sslApiAddress["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);

    // int SSL_write(SSL *ssl, void *buf, int num);
    Interceptor.attach(sslApiAddress["SSL_write"], {
      onEnter: function (args) {
        this.buffer = args[1];
        this.length = args[2].toUInt32();
      },
      onLeave: function (retval) {
        retval |= 0;
        if (retval > 0) {
          console.log(`\n[*] libssl SSL_write called with\n- buffer: ${nativeBufOpFunc(this.buffer, retval)}`);
        }
      },
    });

    // int SSL_read(SSL *ssl, void *buf, int num);
    Interceptor.attach(sslApiAddress["SSL_read"], {
      onEnter: function (args) {
        this.buffer = args[1];
        this.length = args[2].toUInt32();
      },
      onLeave: function (retval) {
        retval |= 0;
        if (retval > 0) {
          console.log(`\n[*] libssl SSL_read called with\n- buffer: ${nativeBufOpFunc(this.buffer, retval)}`);
        }
      },
    });

  }
}

function doJavaHook(classFactory) {
  console.log("\n... start hooking ...");
  const Log = classFactory.use("android.util.Log");
  const Throwable = classFactory.use("java.lang.Throwable");
  const Hexdump = classFactory.use("com.android.internal.util.HexDump");
  const String = classFactory.use("java.lang.String");

  // buffer output function
  // 直接打印字符串格式或以hexdump形式输出
  const javaBufOpFunc = function (bytes, offset, length) {
    let result = "\n";
    if (length > 0) {
      if (useHexDump) {
        result += Hexdump.dumpHexString(bytes, offset, length);
      } else {
        result += String.$new(bytes, offset, length, "UTF-8");
      }
    }
    return result;
  };

  if (hookSocket) {
    const Socket = classFactory.use("java.net.Socket");

    // hook构造函数的五个重载
    // 通过指定的代理连接到远程主机
    Socket.$init.overload("java.net.Proxy").implementation = function (proxy) {
      // print args
      console.log(`\n[*] Socket $init("java.net.Proxy") called with\n- proxy: ${proxy.toString()}`);
      // console.log(`\n[*] proxy address: ${proxy.address().toString()}`);
      // stack trace
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(proxy);
    };
    /*
    // 创建一个流套接字并连接到指定主机上的指定端口
    Socket.$init.overload("java.lang.String", "int").implementation = function (host, port) {
      // print args
      console.log(`\n[*] Socket $init("java.lang.String", "int") called with\n- host: ${host}\n- port: ${port}`);
      // stack trace
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(host, port);
    };
    // 创建一个流套接字并连接到指定地址的指定端口
    Socket.$init.overload("java.net.InetAddress", "int").implementation = function (address, port) {
      // print args
      console.log(`\n[*] Socket $init("java.net.InetAddress", "int") called with\n- host: ${address.toString()}\n- port: ${port}`);
      // stack trace
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(address, port);
    };
    // 创建一个流套接字并连接到指定主机的指定端口，使用指定的本地地址和端口
    Socket.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").implementation = function (host, port, localAddr, localPort) {
      // print args
      console.log(`\n[*] Socket $init("java.lang.String", "int", "java.net.InetAddress", "int") called with\n- host: ${host}\n- port: ${port}\n- localAddr: ${localAddr.toString()}\n- localPort: ${localPort}`);
      // stack trace
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(host, port, localAddr, localPort);
    }
    // 创建一个流套接字并连接到指定地址的指定端口，使用指定的本地地址和端口
    Socket.$init.overload("java.net.InetAddress", "int", "java.net.InetAddress", "int").implementation = function (address, port, localAddr, localPort) {
      // print args
      console.log(`\n[*] Socket $init("java.net.InetAddress", "int", "java.net.InetAddress", "int") called with\n- host: ${address.toString()}\n- port: ${port}\n- localAddr: ${localAddr.toString()}\n- localPort: ${localPort}`);
      // stack trace
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(address, port, localAddr, localPort);
    };
    */
    // 上面四个最终都调用这个构造函数 因此hook一个就够了 
    // private Socket(InetAddress[] addresses, int port, SocketAddress localAddr, boolean stream)
    Socket.$init.overload("[Ljava.net.InetAddress;", "int", "java.net.SocketAddress", "boolean").implementation = function (addresses, port, localAddr, stream) {
      // print args
      console.log(`\n[*] Socket $init("[Ljava.net.InetAddress;", "int", "java.net.SocketAddress", "boolean") called with\n- addresses: ${addresses.toString()}\n- port: ${port}\n- localAddr: ${localAddr ? localAddr.toString() : null}\n- stream: ${stream}`);
      // stack trace
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(addresses, port, localAddr, stream);
    };
  }

  if (hookTcp) {
    // TCP 收发
    const SocketInputStream = classFactory.use("java.net.SocketInputStream");
    const SocketOutputStream = classFactory.use("java.net.SocketOutputStream");

    // 原生私有函数socketWrite0 没有重载
    SocketOutputStream.socketWrite0.implementation = function (fd, buffer, offset, length) {
      // FileDescriptor 暂时用不到 不打印了
      // 获取外部类的属性用 this.this$0.value.xxx.value
      console.log(`\n[*] SocketOutputStream socketWrite0 called with\n- socket: ${this.socket.value.toString()}\n- buffer: ${javaBufOpFunc(buffer, offset, length)}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.socketWrite0(fd, buffer, offset, length);
    };

    SocketInputStream.socketRead0.implementation = function (fd, buffer, offset, length, timeout) {
      // FileDescriptor 暂时用不到 不打印了
      // const inputStr = javaString.$new(buffer);
      const retval = this.socketRead0(fd, buffer, offset, length, timeout);
      console.log(`\n[*] SocketInputStream socketRead0 called with\n- socket: ${this.socket.value.toString()}\n- buffer: ${javaBufOpFunc(buffer, offset, length)}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return retval;
    };
  }

  if (hookUdp) {
    // UDP 发送
    const Linux = classFactory.use("libcore.io.Linux");
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int").implementation = function (fd, buffer, offset, length, flags, inetAddress, port) {
      const bytes = classFactory.array("byte", buffer);
      console.log(`\n[*] Linux sendtoBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int") called with\n- buffer: ${javaBufOpFunc(bytes, offset, length)}\n- inetAddress: ${inetAddress}\n- port: ${port}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.sendtoBytes(fd, buffer, offset, length, flags, inetAddress, port);
    };
    // 可能需要把 SocketAddress 通过 classFactory.cast 强转为具体类型 才能调用toString()方法 
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress").implementation = function (fd, buffer, offset, length, flags, address) {
      const bytes = classFactory.array("byte", buffer);
      console.log(`\n[*] Linux sendtoBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress") called with\n- buffer: ${javaBufOpFunc(bytes, offset, length)}\n- address: ${address.toString()}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.sendtoBytes(fd, buffer, offset, length, flags, address);
    };
    // UDP 接收
    // 最好不写负载 因为不同版本代码有改动
    // Linux.recvfromBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress").implementation = function (fd, buffer, offset, length, flags, srcAddress) {
    // Linux.recvfromBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetSocketAddress").implementation = function (fd, buffer, offset, length, flags, srcAddress) {
    Linux.recvfromBytes.implementation = function (fd, buffer, offset, length, flags, srcAddress) {
      const bytes = classFactory.array("byte", buffer);
      // console.log(`\n[*] Linux recvfromBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress") called with\n- buffer: ${hexdump4j(bytes)}\n- address: ${srcAddress.toString()}`);
      // console.log(`\n[*] Linux recvfromBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetSocketAddress") called with\n- buffer: ${hexdump4j(bytes)}\n- address: ${srcAddress.toString()}`);
      console.log(`\n[*] Linux recvfromBytes called with\n- buffer: ${javaBufOpFunc(bytes, offset, length)}\n- address: ${srcAddress.toString()}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.recvfromBytes(fd, buffer, offset, length, flags, srcAddress);
    };
  }

  // 暂时没发现有什么用
  if (hookConscrypt) {
    const NativeCrypto = Java.use("com.android.org.conscrypt.NativeCrypto");
    NativeCrypto.SSL_write.implementation = function (
      ssl, ssl_holder, fd, shc, buffer, offset, length, writeTimeoutMillis
    ) {
      console.log(`\n[*] NativeCrypto SSL_write called with\n- buffer: ${javaBufOpFunc(buffer, offset, length)}\n`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.SSL_write(ssl, ssl_holder, fd, shc, buffer, offset, length, writeTimeoutMillis);
    };
    NativeCrypto.SSL_read.implementation = function (
      ssl, ssl_holder, fd, shc, buffer, offset, length, readTimeoutMillis
    ) {
      const retval = this.SSL_read(ssl, ssl_holder, fd, shc, buffer, offset, length, readTimeoutMillis);
      console.log(`\n[*] NativeCrypto SSL_read called with\n- buffer: ${javaBufOpFunc(buffer, offset, length)}\n`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return retval;
    };
  }
}

setImmediate(main);
