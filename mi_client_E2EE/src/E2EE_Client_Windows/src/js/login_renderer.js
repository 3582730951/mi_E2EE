const api = window.electronAPI;

document.getElementById('btn-min').onclick = () => api.loginMin();
document.getElementById('btn-close').onclick = () => api.loginClose();

const btnLogin = document.getElementById('btn-login');
const userIn = document.getElementById('username');
const passIn = document.getElementById('password');

btnLogin.onclick = async () => {
    const user = userIn.value.trim();
    const pass = passIn.value.trim();

    if (!user || !pass) {
        alert("请输入账号和密码");
        return;
    }

    btnLogin.innerText = "安全连接中...";
    btnLogin.disabled = true;

    try {
        // 1. 初始化 SDK
        await api.core.init("./userdata"); 
        
        // 2. 建立 KCP 连接 (默认配置)
        await api.core.connect("127.0.0.1", 19999);
        
        btnLogin.innerText = "身份验证中...";
        
        // 3. 执行登录 (加密传输)
        await api.core.login(user, pass);
        
        // 4. 成功跳转
        api.loginSuccess();
        
    } catch (err) {
        console.error(err);
        alert("登录失败: " + err);
        btnLogin.innerText = "登录";
        btnLogin.disabled = false;
    }
};
