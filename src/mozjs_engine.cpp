/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   mozjs_engine.cpp
 * Author: alex
 * 
 * Created on May 8, 2018, 9:59 PM
 */

#include "mozjs_engine.hpp"

#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#define alignas(VAL) __attribute__ ((aligned(VAL)))
#include "jsapi.h"
#include "js/Initialization.h"
#include "js/Conversions.h"

#include "utf8.h"

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wiltoncall.h"
#include "wilton/wilton_loader.h"

#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"

namespace wilton {
namespace mozjs {

namespace { // anonymous

JSClassOps global_ops = {
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    JS_GlobalObjectTraceHook
};

/* The class of the global object. */
JSClass global_class = {
    "global",
    JSCLASS_GLOBAL_FLAGS,
    &global_ops
};

std::string jsval_to_string(JSContext* ctx, JS::HandleValue val) STATICLIB_NOEXCEPT {
    auto sval_ptr = JS::ToString(ctx, val);
    if (nullptr != sval_ptr) {
        JS::RootedString sval(ctx, sval_ptr);
        auto str_ptr = JS_EncodeStringToUTF8(ctx, sval);
        if (nullptr != str_ptr) {
            return std::string(str_ptr);
        }
    }
    return std::string();
}

JSString* string_to_jsval(JSContext* ctx, const char* str, size_t str_len) {
    auto uvec = std::vector<uint16_t>();
    utf8::utf8to16(str, str + str_len, std::back_inserter(uvec));
    // proper check is untrivial here
    return JS_NewUCStringCopyN(ctx, reinterpret_cast<const char16_t*>(uvec.data()), uvec.size());
}

JSString* string_to_jsval(JSContext* ctx, const std::string& str) {
    return string_to_jsval(ctx, str.data(), str.length());
}

std::string format_stack_trace(JSContext* ctx) STATICLIB_NOEXCEPT {
    auto default_msg = std::string("MozJS error");
    auto err_pending = JS_IsExceptionPending(ctx);
    if (!err_pending) {
        return default_msg;
    }
    JS::RootedValue exc(ctx);
    auto err_get = JS_GetPendingException(ctx, std::addressof(exc));
    if (!err_get) {
        return default_msg;
    }
    JS_ClearPendingException(ctx);
    if (!exc.isObject() || exc.isNull()) {
        return default_msg;
    }
    JS::RootedObject exc_obj(ctx, exc.toObjectOrNull());
    JS::RootedValue stack_val(ctx);
    auto err_stack = JS_GetProperty(ctx, exc_obj, "stack", std::addressof(stack_val));
    if (!err_stack) {
        return default_msg;
    }
    auto stack = jsval_to_string(ctx, stack_val);
    auto msg = jsval_to_string(ctx, exc);
    if (msg.empty()) {
        msg = default_msg;
    }
    if (stack.length() > 0) {
        msg.push_back('\n');
        msg.append(stack);
    }
    // filter and format
    auto vec = sl::utils::split(msg, '\n');
    auto res = std::string();
    for (size_t i = 0; i < vec.size(); i++) {
        auto& line = vec.at(i);
        if(line.length() > 1 && !(std::string::npos != line.find("@wilton-requirejs/require.js:")) &&
                !(std::string::npos != line.find("@wilton-require.js:"))) {
            if (!sl::utils::starts_with(line, "    at ") && 
                    !sl::utils::starts_with(line, "Error:")) {
                res.append("    at ");
            }
            res += line;
            res.push_back('\n');
        }
    }
    while (res.length() > 0 && '\n' == res.back()) {
        res.pop_back();
    }
    return res;
}

void register_c_func(JSContext* ctx, JS::RootedObject& global, const std::string& name,
        JSNative cb, uint8_t nargs) {
    auto err = JS_DefineFunction(ctx, global, name.c_str(), cb, nargs, 0);
    if (nullptr == err) {
        auto msg = format_stack_trace(ctx);
        throw support::exception(TRACEMSG(msg));
    }
}

std::string eval_js(JSContext* ctx, const char* code, size_t code_len, const std::string& path) {
    JS::CompileOptions opts(ctx);
    opts.setFileAndLine(path.c_str(), 1);
    opts.setUTF8(true);
    JS::RootedValue rval(ctx);
    bool success = JS::Evaluate(ctx, opts, code, code_len, std::addressof(rval));
    if (!success) {
        auto msg = format_stack_trace(ctx);
        throw support::exception(TRACEMSG(msg));
    }

    return jsval_to_string(ctx, rval);
}

void throw_js_exception(JSContext* ctx, const std::string& msg) {
    // JS::CreateError is cumbersome
    auto json = sl::json::value({
        {"message", msg},
        {"stack", ""}
    });
    auto str = json.dumps();
    auto str_ptr = string_to_jsval(ctx, str);
    JS::RootedString str_val(ctx, str_ptr);
    JS::RootedValue exc(ctx);
    auto err = JS_ParseJSON(ctx, str_val, std::addressof(exc));
    if (!err) {
        auto sptr = string_to_jsval(ctx, msg);
        auto sval = JS::StringValue(sptr);
        JS::RootedValue rsval(ctx, sval);
        JS_SetPendingException(ctx, rsval);
    }
    JS_SetPendingException(ctx, exc);
}

bool print_func(JSContext* ctx, unsigned argc, JS::Value* vp) STATICLIB_NOEXCEPT {
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    if (argc > 0) {
        auto val = jsval_to_string(ctx, args[0]);
        puts(val.c_str());
    } else {
        puts("");
    }
    return true;
}

bool load_func(JSContext* ctx, unsigned argc, JS::Value* vp) STATICLIB_NOEXCEPT {
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    JSAutoRequest ar(ctx);

    auto path = std::string();
    try {
        // check args
        if (args.length() < 1 || !args[0].isString()) {
            throw support::exception(TRACEMSG("Invalid arguments specified"));
        }

        // load code
        path = jsval_to_string(ctx, args[0]);
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        auto deferred = sl::support::defer([code] () STATICLIB_NOEXCEPT {
            wilton_free(code);
        });
        auto path_short = support::script_engine_map_detail::shorten_script_path(path);
        wilton::support::log_debug("wilton.engine.mozjs.eval",
                "Evaluating source file, path: [" + path + "] ...");
        eval_js(ctx, code, static_cast<size_t>(code_len), path_short);
        wilton::support::log_debug("wilton.engine.mozjs.eval", "Eval complete");
        return true;
    } catch (const std::exception& e) {
        auto msg = TRACEMSG(e.what() + "\nError loading script, path: [" + path + "]");
        throw_js_exception(ctx, msg);
        return false;
    } catch (...) {
        auto msg = TRACEMSG("Error(...) loading script, path: [" + path + "]");
        throw_js_exception(ctx, msg);
        return false;
    }
}

bool wiltoncall_func(JSContext* ctx, unsigned argc, JS::Value* vp) STATICLIB_NOEXCEPT {
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    JSAutoRequest ar(ctx);

    if (args.length() < 2 || !args[0].isString() || !args[1].isString()) {
        auto msg = TRACEMSG("Invalid arguments specified");
        throw_js_exception(ctx, msg);
        return false;
    }
    auto name = jsval_to_string(ctx, args[0]);
    auto input = jsval_to_string(ctx, args[1]);
    char* out = nullptr;
    int out_len = 0;
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Performing a call,  input length: [" + sl::support::to_string(input.length()) + "] ...");
    auto err = wiltoncall(name.c_str(), static_cast<int> (name.length()),
            input.c_str(), static_cast<int> (input.length()),
            std::addressof(out), std::addressof(out_len));
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Call complete, result: [" + (nullptr != err ? std::string(err) : "") + "]");
    if (nullptr == err) {
        if (nullptr != out) {
            auto deferred = sl::support::defer([out]() STATICLIB_NOEXCEPT {
                wilton_free(out);
            });
            auto sptr = string_to_jsval(ctx, out, static_cast<size_t>(out_len));
            args.rval().set(JS::StringValue(sptr));
            return true;
        } else {
            args.rval().set(JS::NullValue());
            return true;
        }
    } else {
        auto deferred = sl::support::defer([err]() STATICLIB_NOEXCEPT {
            wilton_free(err);
        });
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        throw_js_exception(ctx, msg);
        return false;
    }
}

} // namespace

class mozjs_engine::impl : public sl::pimpl::object::impl {
    JSContext* ctx;
    std::unique_ptr<JS::RootedObject> global_ptr;

public:

    ~impl() STATICLIB_NOEXCEPT {
        if (nullptr != ctx) {
            {
                JSAutoRequest ar(ctx);
                JS_GC(ctx);
            }
            global_ptr.reset();
            JS_DestroyContext(ctx);
        }
    }

    impl(sl::io::span<const char> init_code) {
        wilton::support::log_info("wilton.engine.mozjs.init", "Initializing engine instance ...");
        this->ctx = JS_NewContext(JS::DefaultHeapMaxBytes);
        if (nullptr == this->ctx) throw support::exception(TRACEMSG("'JS_NewContext' error"));
        JS_SetContextPrivate(ctx, this);

        auto err_init = JS::InitSelfHostedCode(ctx);
        if (!err_init) throw support::exception(TRACEMSG("'JS::InitSelfHostedCode' error"));

        JSAutoRequest ar(ctx);
        JS::CompartmentOptions options;
        auto global_obj = JS_NewGlobalObject(ctx, &global_class, nullptr, JS::FireOnNewGlobalHook, options);
        if (nullptr == global_obj) throw support::exception(TRACEMSG("'JS_NewGlobalObject' error" ));
        this->global_ptr.reset(new JS::RootedObject(ctx, global_obj));
        auto& global = *global_ptr;

        JSAutoCompartment ac(ctx, global);
        JS_InitStandardClasses(ctx, global);
    
        register_c_func(ctx, global, "print", print_func, 1);
        register_c_func(ctx, global, "WILTON_load", load_func, 1);
        register_c_func(ctx, global, "WILTON_wiltoncall", wiltoncall_func, 2);
        eval_js(ctx, init_code.data(), init_code.size(), "wilton-require.js");

        wilton::support::log_info("wilton.engine.mozjs.init", "Engine initialization complete");
    }

    support::buffer run_callback_script(mozjs_engine&, sl::io::span<const char> callback_script_json) {
        wilton::support::log_debug("wilton.engine.mozjs.run",
                "Running callback script: [" + std::string(callback_script_json.data(), callback_script_json.size()) + "] ...");
        auto& global = *global_ptr;
        JSAutoRequest ar(ctx);
        JSAutoCompartment ac(ctx, global);

        // call
        auto sptr = string_to_jsval(ctx, callback_script_json.data(), callback_script_json.size());
        auto sval = JS::StringValue(sptr);
        JS::RootedValue rsval(ctx, sval);
        JS::HandleValueArray args(rsval);
        JS::RootedValue res(ctx);
        auto err = JS_CallFunctionName(ctx, global, "WILTON_run", args, std::addressof(res));
        wilton::support::log_debug("wilton.engine.mozjs.run",
                "Callback run complete, result: [" + sl::support::to_string_bool(err) + "]");
        if (!err) {
            auto msg = format_stack_trace(ctx);
            throw support::exception(TRACEMSG(msg));
        }
        if (res.isString()) {
            auto str = jsval_to_string(ctx, res);
            return support::make_string_buffer(str);
        }
        return support::make_null_buffer();
    }

    void run_garbage_collector(mozjs_engine&) {
        JSAutoRequest ar(ctx);
        JS_GC(ctx);
    }

    static void initialize() {
        JS_Init();
    }

};

PIMPL_FORWARD_CONSTRUCTOR(mozjs_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(mozjs_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(mozjs_engine, void, run_garbage_collector, (), (), support::exception)
PIMPL_FORWARD_METHOD_STATIC(mozjs_engine, void, initialize, (), (), support::exception)

} // namespace
}
