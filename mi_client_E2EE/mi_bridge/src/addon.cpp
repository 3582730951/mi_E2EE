#include <napi.h>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <memory>

extern "C" {
#include "../../include/mi_common.h"
#include "../include/mi_client_api.h"
}

namespace {

ConfigStruct g_cfg{};
Napi::ThreadSafeFunction g_msg_tsfn;
Napi::FunctionReference g_raw_send_ref;
Napi::FunctionReference g_raw_recv_ref;
std::string g_workdir;

std::string EncJsonToString(const EncJson* enc) {
    if (!enc || !enc->data || enc->len == 0) return {};
    return std::string(reinterpret_cast<const char*>(enc->data), enc->len);
}

void MessageCallback(const EncJson* msg) {
    if (g_msg_tsfn) {
        std::string payload = EncJsonToString(msg);
        g_msg_tsfn.BlockingCall([payload](Napi::Env env, Napi::Function jsCallback) {
            jsCallback.Call({ Napi::String::New(env, payload) });
        });
    }
}

EncString MakeEncString(const std::string& s) {
    EncString enc{};
    MI_CreateEncString(s.c_str(), &enc);
    return enc;
}

void FreeEncStringLocal(EncString& enc) {
    MI_FreeEncString(&enc);
}

EncJson MakeEncJson(const std::string& s) {
    EncJson enc{};
    MI_CreateEncJsonFromString(s.c_str(), &enc);
    return enc;
}

void FreeEncJsonLocal(EncJson& enc) {
    MI_FreeEncJson(&enc);
}

Napi::Value Init(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "storagePath required").ThrowAsJavaScriptException();
        return env.Null();
    }
    g_workdir = info[0].As<Napi::String>().Utf8Value();
    g_cfg.work_dir = g_workdir.c_str();
    g_cfg.log_level = 0;
    g_cfg.enable_hardware_crypto = 0;
    g_cfg.server_ip = "127.0.0.1";
    g_cfg.server_port = MI_DEFAULT_PORT;
    MI_Result r = MI_Init(&g_cfg);
    return Napi::Boolean::New(env, r == MI_OK);
}

Napi::Value Shutdown(const Napi::CallbackInfo& info) {
    (void)info;
    MI_Shutdown();
    return info.Env().Undefined();
}

Napi::Value GetStatus(const Napi::CallbackInfo& info) {
    (void)info;
    return Napi::Number::New(info.Env(), MI_KCP_Status());
}

Napi::Value Connect(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string ip = (info.Length() > 0 && info[0].IsString()) ? info[0].As<Napi::String>().Utf8Value() : std::string("127.0.0.1");
    int port = info.Length() > 1 && info[1].IsNumber() ? info[1].As<Napi::Number>().Int32Value() : MI_DEFAULT_PORT;
    EncString ip_enc = MakeEncString(ip);
    MI_Result r = MI_KCP_Connect(ip_enc, port);
    MI_FreeEncString(&ip_enc);
    return Napi::Boolean::New(env, r == MI_OK);
}

Napi::Value Login(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "username, password required").ThrowAsJavaScriptException();
        return env.Null();
    }
    std::string user = info[0].As<Napi::String>();
    std::string pass = info[1].As<Napi::String>();
    EncString u = MakeEncString(user);
    EncString p = MakeEncString(pass);
    MI_Result r = MI_Login(u, p);
    MI_FreeEncString(&u);
    MI_FreeEncString(&p);
    return Napi::Boolean::New(env, r == MI_OK);
}

Napi::Value SendMessage(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "targetId, content required").ThrowAsJavaScriptException();
        return env.Null();
    }
    std::string target = info[0].As<Napi::String>();
    std::string content = info[1].As<Napi::String>();
    EncString t = MakeEncString(target);
    EncJson j = MakeEncJson(content);
    MI_Result r = MI_SendMessage(t, j);
    MI_FreeEncString(&t);
    MI_FreeEncJson(&j);
    return Napi::Boolean::New(env, r == MI_OK);
}

Napi::Value RegisterCallback(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "callback required").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (g_msg_tsfn) {
        g_msg_tsfn.Release();
    }
    g_msg_tsfn = Napi::ThreadSafeFunction::New(env, info[0].As<Napi::Function>(), "msg_cb", 0, 1);
    MI_RegisterMessageCallback(MessageCallback);
    return env.Undefined();
}

Napi::Value SecureDelete(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "path required").ThrowAsJavaScriptException();
        return env.Null();
    }
    std::string path = info[0].As<Napi::String>();
    MI_Result r = MI_SecureEraseFile(path.c_str(), 0);
    return Napi::Boolean::New(env, r == MI_OK);
}

bool RawSendBridge(const uint8_t* data, size_t len) {
    if (g_raw_send_ref.IsEmpty()) return false;
    Napi::Env env = g_raw_send_ref.Env();
    Napi::HandleScope scope(env);
    Napi::Buffer<uint8_t> buf = Napi::Buffer<uint8_t>::Copy(env, data, len);
    try {
        Napi::Value ret = g_raw_send_ref.Value().Call({buf});
        if (ret.IsBoolean()) return ret.As<Napi::Boolean>().Value();
        return true;
    } catch (...) {
        return false;
    }
}

void RawRecvBridge(const uint8_t* data, size_t len) {
    if (g_raw_recv_ref.IsEmpty()) return;
    Napi::Env env = g_raw_recv_ref.Env();
    Napi::HandleScope scope(env);
    Napi::Buffer<uint8_t> buf = Napi::Buffer<uint8_t>::Copy(env, data, len);
    try {
        g_raw_recv_ref.Value().Call({buf});
    } catch (...) {
        // swallow JS exceptions in bridge
    }
}

Napi::Object InitAddon(Napi::Env env, Napi::Object exports) {
    exports.Set("init", Napi::Function::New(env, Init));
    exports.Set("shutdown", Napi::Function::New(env, Shutdown));
    exports.Set("getStatus", Napi::Function::New(env, GetStatus));
    exports.Set("connect", Napi::Function::New(env, Connect));
    exports.Set("login", Napi::Function::New(env, Login));
    exports.Set("sendMessage", Napi::Function::New(env, SendMessage));
    exports.Set("onMessage", Napi::Function::New(env, RegisterCallback));
    exports.Set("secureDelete", Napi::Function::New(env, SecureDelete));
    exports.Set("setRawSend", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1 || !info[0].IsFunction()) {
            Napi::TypeError::New(env, "fn required").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        Napi::Function fn = info[0].As<Napi::Function>();
        g_raw_send_ref.Reset(fn, 1);
        MI_SetRawSend(&RawSendBridge);
        return env.Undefined();
    }));
    exports.Set("setRawReceive", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1 || !info[0].IsFunction()) {
            Napi::TypeError::New(env, "fn required").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        Napi::Function fn = info[0].As<Napi::Function>();
        g_raw_recv_ref.Reset(fn, 1);
        MI_SetRawReceive(&RawRecvBridge);
        return env.Undefined();
    }));
    return exports;
}

} // namespace

NODE_API_MODULE(mi_bridge, InitAddon)
