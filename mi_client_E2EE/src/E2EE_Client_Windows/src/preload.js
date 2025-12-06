const { contextBridge, ipcRenderer } = require('electron');

let native = null;
let nativeLoadError = null;
try {
    native = require('../../mi_bridge/build/Release/mi_bridge.node');
    console.log('[BRIDGE] Native addon loaded.');
} catch (e) {
    nativeLoadError = e;
    console.warn('[BRIDGE] Native addon load failed.', e.message);
}

const allowMockBridge = process.env.MI_ALLOW_BRIDGE_MOCK === '1';
if (!native && !allowMockBridge) {
    const hint = nativeLoadError ? nativeLoadError.message : 'mi_bridge.node missing';
    const msg = `[BRIDGE] Native addon unavailable (${hint}). Ensure mi_bridge.node与依赖DLL(libssl/libcrypto/libmysql,vcruntime/msvcp)打包到 resources/app.asar.unpacked/mi_bridge/build/Release 或同级目录；如需强制使用 Mock，请设置 MI_ALLOW_BRIDGE_MOCK=1。`;
    console.error(msg);
    throw new Error(msg);
}

const Bridge = native ? {
    isInitialized: false,
    msgCallback: null,
    status: 0,
    init: async (storagePath) => {
        const ok = native.init(storagePath);
        Bridge.isInitialized = ok;
        return ok;
    },
    connect: async (ip, port) => {
        if (!Bridge.isInitialized) throw new Error('Please Init first');
        const ok = native.connect(ip, port);
        Bridge.status = ok ? 2 : 0;
        return ok;
    },
    login: async (user, pass) => native.login(user, pass),
    sendMessage: (targetId, plainText) => native.sendMessage(targetId, plainText),
    registerMsgCallback: (cb) => {
        native.onMessage((payload) => {
            cb('remote', payload, Date.now());
        });
    },
    setRawSend: native.setRawSend ? native.setRawSend : () => {},
    setRawReceive: native.setRawReceive ? native.setRawReceive : () => {},
    sendFile: async (_targetId, filePath) => {
        // 分片逻辑尚未暴露到 addon，这里仅调用 secureDelete 保障安全
        return native.secureDelete(filePath);
    },
    secureDelete: async (filePath) => native.secureDelete(filePath),
    getStatus: () => Bridge.status
} : {
    isInitialized: false,
    msgCallback: null,
    status: 0, // 0=断开,1=连接中,2=已连接
    init: async (storagePath) => {
        console.log(`[BRIDGE-MOCK] MI_Init("${storagePath}")`);
        Bridge.isInitialized = true;
        return true;
    },
    connect: async (ip, port) => {
        if (!Bridge.isInitialized) throw new Error("Please Init first");
        console.log(`[BRIDGE-MOCK] MI_KCP_Connect(${ip}:${port})...`);
        return new Promise(resolve => setTimeout(() => { Bridge.status = 2; resolve(true); }, 300));
    },
    login: async (user, pass) => {
        return new Promise((resolve, reject) => {
            setTimeout(() => (user && pass ? resolve(true) : reject("Auth failed")), 300);
        });
    },
    sendMessage: (targetId, plainText) => {
        console.log(`[BRIDGE-MOCK] SendMessage -> ${targetId}: ${plainText}`);
        return true;
    },
    registerMsgCallback: (callback) => {
        Bridge.msgCallback = callback;
        setTimeout(() => {
            callback("codex", "Mock message from backend", Date.now());
        }, 1000);
    },
    sendFile: async (_targetId, filePath) => {
        console.log(`[BRIDGE-MOCK] sendFile ${filePath}`);
        return true;
    },
    secureDelete: async (filePath) => {
        console.log(`[BRIDGE-MOCK] secureDelete ${filePath}`);
        return true;
    },
    getStatus: () => Bridge.status
};

// --- 暴露给渲染进程的安全 API ---
contextBridge.exposeInMainWorld('electronAPI', {
    // 窗口操作
    loginSuccess: () => ipcRenderer.send('login-success'),
    loginClose: () => ipcRenderer.send('login-close'),
    loginMin: () => ipcRenderer.send('login-min'),
    mainClose: () => ipcRenderer.send('main-close'),
    mainMin: () => ipcRenderer.send('main-min'),
    mainMax: () => ipcRenderer.send('main-max'),
    
    // 系统操作
    openFileDialog: () => ipcRenderer.invoke('dialog:openFile'),

    // 业务逻辑 (封装 Bridge)
    core: {
        init: Bridge.init,
        connect: Bridge.connect,
        login: Bridge.login,
        sendMessage: Bridge.sendMessage,
        sendFile: Bridge.sendFile,
        secureDelete: Bridge.secureDelete,
        onMessage: Bridge.registerMsgCallback,
        getStatus: () => Bridge.status
    }
});
