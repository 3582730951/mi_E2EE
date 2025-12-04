const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');

let loginWindow;
let mainWindow;

// --- 1. 登录窗口 ---
function createLoginWindow() {
    loginWindow = new BrowserWindow({
        width: 320, height: 480,
        frame: false, resizable: false, transparent: true,
        webPreferences: {
            preload: path.join(__dirname, 'src/preload.js'),
            contextIsolation: true, nodeIntegration: false
        }
    });
    loginWindow.loadFile('src/login.html');
    loginWindow.center();
}

// --- 2. 主界面窗口 ---
function createMainWindow() {
    mainWindow = new BrowserWindow({
        width: 960, height: 700,
        minWidth: 800, minHeight: 600,
        frame: false, backgroundColor: '#F2F2F2',
        webPreferences: {
            preload: path.join(__dirname, 'src/preload.js'),
            contextIsolation: true, nodeIntegration: false
        }
    });
    mainWindow.loadFile('src/index.html');
    mainWindow.center();

    // 窗口控制
    ipcMain.on('main-min', () => mainWindow.minimize());
    ipcMain.on('main-max', () => {
        mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
    });
    ipcMain.on('main-close', () => app.quit());
}

app.whenReady().then(() => {
    createLoginWindow();

    // 监听登录成功，切换窗口
    ipcMain.on('login-success', () => {
        if (loginWindow) {
            loginWindow.close();
            loginWindow = null;
        }
        createMainWindow();
    });

    // 登录窗控制
    ipcMain.on('login-close', () => app.quit());
    ipcMain.on('login-min', () => loginWindow.minimize());

    // ★ 新增：处理文件选择请求
    ipcMain.handle('dialog:openFile', async () => {
        const { canceled, filePaths } = await dialog.showOpenDialog({
            properties: ['openFile'],
            title: '选择发送文件 (E2EE加密)'
        });
        if (canceled) return null;
        return filePaths[0];
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
