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
 * File:   mozjs_config.hpp
 * Author: alex
 *
 * Created on May 22, 2018, 4:22 PM
 */

#ifndef WILTON_MOZJS_CONFIG_HPP
#define WILTON_MOZJS_CONFIG_HPP

#include <cstdint>

#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

namespace wilton {
namespace mozjs {

class mozjs_config {
public:
    uint32_t heap_max_bytes = 0;
    uint32_t max_nursery_bytes = 0;
    bool option_baseline = true;
    bool option_ion = true;
    bool option_native_regexp = true;

    mozjs_config(const sl::json::value& env_json) {
        for (const sl::json::field& fi : env_json.as_object()) {
            auto& name = fi.name();
            if (sl::utils::starts_with(name, "MOZJS_")) {
                if ("MOZJS_HeapMaxBytes" == name) {
                    this->heap_max_bytes = str_as_u32(fi, name);
                } else if ("MOZJS_MaxNurseryBytes" == name) {
                    this->max_nursery_bytes = str_as_u32(fi, name);
                } else if ("MOZJS_OptionBaseline" == name) {
                    this->option_baseline = str_as_bool(fi, name);
                } else if ("MOZJS_OptionIon" == name) {
                    this->option_ion = str_as_bool(fi, name);
                } else if ("MOZJS_OptionNativeRegExp" == name) {
                    this->option_native_regexp = str_as_bool(fi, name);
                } else {
                    throw support::exception(TRACEMSG("Unknown 'mozjs_config' field: [" + name + "]"));
                }
            }
        }
    }

    mozjs_config(const mozjs_config& other):
    heap_max_bytes(other.heap_max_bytes),
    max_nursery_bytes(other.max_nursery_bytes),
    option_baseline(other.option_baseline),
    option_ion(other.option_ion),
    option_native_regexp(other.option_native_regexp) { }

    mozjs_config& operator=(const mozjs_config& other) {
        this->heap_max_bytes = other.heap_max_bytes;
        this->max_nursery_bytes = other.max_nursery_bytes;
        this->option_baseline = other.option_baseline;
        this->option_ion = other.option_ion;
        this->option_native_regexp = other.option_native_regexp;
        return *this;
    }
 
    sl::json::value to_json() const {
        return {
            { "HeapMaxBytes", heap_max_bytes },
            { "MaxNurseryBytes", max_nursery_bytes },
            { "OptionBaseline", option_baseline },
            { "OptionIon", option_ion },
            { "OptionNativeRegExp", option_native_regexp }
        };
    }

private:

    static uint32_t str_as_u32(const sl::json::field& fi, const std::string& name) {
        auto str = fi.as_string_nonempty_or_throw(name);
        try {
            return sl::utils::parse_uint32(str);
        } catch (std::exception& e) {
            throw support::exception(TRACEMSG(e.what() + 
                    "\nError parsing parameter: [" + name + "], value: [" + str + "]"));
        }
    }

    static bool str_as_bool(const sl::json::field& fi, const std::string& name) {
        auto str = fi.as_string_nonempty_or_throw(name);
        if ("true" == str) {
            return true;
        }
        if ("false" == str) {
            return false;
        }
        throw support::exception(TRACEMSG("Error parsing parameter: [" + name + "]," +
                " value: [" + str + "]"));
    }
};

} // namespace
}

#endif /* WILTON_MOZJS_CONFIG_HPP */

