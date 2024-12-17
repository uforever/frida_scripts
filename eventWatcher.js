let classFactory = null;
let javaClass = null;
let javaObject = null;

function main() {
  Java.perform(doJavaHook);
}

function doJavaHook() {
  const Application = Java.use("android.app.Application");
  Application.attach.overload("android.content.Context").implementation = function (context) {
    this.attach(context);
    const classLoader = context.getClassLoader();
    classFactory = Java.ClassFactory.get(classLoader);
  };
  if (classFactory) {
    console.log("[!] with shell");
  } else {
    classFactory = Java;
    console.log("[!] without shell");
  }
  hookOnClickListener();
}

function hookOnClickListener() {
  // spawn
  classFactory.use("android.view.View").setOnClickListener.implementation = function (listener) {
    if (listener) {
      watch(listener, "onClick");
    }
    this.setOnClickListener(listener);
  };

  // attach
  classFactory.choose("android.view.View$ListenerInfo", {
    onMatch: function (instance) {
      const listener = instance.mOnClickListener.value;
      if (listener) {
        watch(listener, 'onClick');
      }
    },
    onComplete: function () {
    },
  });
}

function watch(obj, mtdName) {
  const listenerClassName = getObjClassName(obj);
  const listenerClass = classFactory.use(listenerClassName);
  if (!listenerClass || !mtdName in listenerClass) {
    return;
  }

  listenerClass[mtdName].overloads.forEach(function (overload) {
    overload.implementation = function () {
      console.log(`[*] Watch Event: ${mtdName} - ${getObjClassName(this)}`);
      return this[mtdName].apply(this, arguments);
    };
  })
}

function getObjClassName(obj) {
  if (!javaClass) {
    javaClass = classFactory.use("java.lang.Class");
  }
  if (!javaObject) {
    javaObject = classFactory.use("java.lang.Object");
  }
  return javaClass.getName.call(javaObject.getClass.call(obj));
}

setImmediate(main);
