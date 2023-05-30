/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#ifndef GDM_PAM_EXTENSIONS_COMMON_H
#define GDM_PAM_EXTENSIONS_COMMON_H

#include <alloca.h>
#include <endian.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <security/pam_appl.h>

#include <glib.h>

/* There's no builtin way to count the number of variadic arguments passed in a macro, so we fake it.
 * If there were no args passed, 10 would be in slot _1, slot _10 would be 1, and N would be 0.
 * But as more args get passed, 10 moves right more and more slots, and 1 and the lower numbers get
 * moved past the named slots into the internal ... part,
 * Because the numbers are sequential and N is closest to the internal ... part, it reflects how many
 * lower numbers are shifted into that ... part, and so it also reflects how many
 * arguments are put in front.
 */
#define GDM_COUNT_ARGS(...)  GDM_COUNT_ARGS_INTERNAL(,##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define GDM_COUNT_ARGS_INTERNAL(_blank, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...) N

#define GDM_NAMESPACE_STRING(x, y) x "." y
#define GDM_NAMESPACE_STRINGS_1(prefix, x) GDM_NAMESPACE_STRING(prefix, x)
#define GDM_NAMESPACE_STRINGS_2(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_1(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_3(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_2(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_4(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_3(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_5(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_4(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_6(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_5(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_7(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x)" " GDM_NAMESPACE_STRINGS_6(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_8(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_7(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_9(prefix, x, ...) GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_8(prefix, __VA_ARGS__)
#define GDM_NAMESPACE_STRINGS_10(prefix, x, ...)(GDM_NAMESPACE_STRING(prefix, x) " " GDM_NAMESPACE_STRINGS_9(prefix, __VA_ARGS__)

#define GDM_PAM_EXTENSION_DEFINE_TYPES(extension, ...) (extension " " G_PASTE(GDM_NAMESPACE_STRINGS_, GDM_COUNT_ARGS(__VA_ARGS__)) (extension, __VA_ARGS__))


typedef struct {
        uint32_t length;

        unsigned char type;
        unsigned char data[];
} GdmPamExtensionMessage;

#define GDM_PAM_EXTENSION_MESSAGE_FROM_PAM_MESSAGE(query) (GdmPamExtensionMessage *) (void *) query->msg
#define GDM_PAM_EXTENSION_MESSAGE_TO_PAM_REPLY(msg) (char *) (void *) msg
#define GDM_PAM_EXTENSION_MESSAGE_TO_BINARY_PROMPT_MESSAGE(extended_message, binary_message) \
{ \
        (binary_message)->msg_style = PAM_BINARY_PROMPT; \
        (binary_message)->msg = (void *) extended_message; \
}
#define GDM_PAM_EXTENSION_MESSAGE_TRUNCATED(msg) be32toh(msg->length) < sizeof (GdmPamExtensionMessage)
#define GDM_PAM_EXTENSION_MESSAGE_INVALID_TYPE(msg) \
({ \
        bool _invalid = true; \
        int _n = -1; \
        const char *_supported_extensions; \
        _supported_extensions = getenv ("GDM_SUPPORTED_PAM_EXTENSIONS"); \
        if (_supported_extensions != NULL) { \
                const char *_p = _supported_extensions; \
                while (*_p != '\0' && _n < UCHAR_MAX) { \
                        size_t _length; \
                        _length = strcspn (_p, " "); \
                        if (_length > 0) \
                                _n++; \
                        _p += _length; \
                        _length = strspn (_p, " "); \
                        _p += _length; \
                } \
                if (_n >= msg->type) \
                        _invalid = false; \
        } \
        _invalid; \
})

bool GDM_PAM_EXTENSION_MESSAGE_MATCH(GdmPamExtensionMessage *msg, char **supported_extensions, const char *name)
{
        bool _match = FALSE;
        int _t = -1, _i = 0;
        int _name_length;
        _name_length = strlen (name);
        for (_i = 0; supported_extensions[_i] != NULL && !_match; _i++) {
                const char *_p = supported_extensions[_i];
                while (*_p != '\0' && _t < UCHAR_MAX) {
                        size_t _length;
                        _length = strcspn (_p, " ");
                        if (_length > 0)
                                _t++;
                        if (_length == _name_length && strncmp (name, _p, _length) == 0) {
                                _match = _t == msg->type;
                                break;
                        }
                        _p += _length;
                        _length = strspn (_p, " ");
                        _p += _length;
                }
        }
        return _match;
}

#if 0
#define GDM_PAM_EXTENSION_MESSAGE_MATCH(msg, supported_extensions, name) \
({ \
        bool _match = FALSE; \
        int _t = -1, _i = 0; \
        int _name_length; \
        _name_length = strlen (name); \
        for (_i = 0; supported_extensions[_i] != NULL && !_match; _i++) { \
                const char *_p = supported_extensions[_i]; \
                while (*_p != '\0' && _t < UCHAR_MAX) { \
                        size_t _length; \
                        _length = strcspn (_p, " "); \
                        if (_length > 0) \
                                _t++; \
                        if (_length == _name_length && strncmp (name, _p, _length) == 0) { \
                                _match = _t == msg->type; \
                                break; \
                        } \
                        _p += _length; \
                        _length = strspn (_p, " "); \
                        _p += _length; \
                } \
        } \
        _match; \
})
#endif

/* environment block should be a statically allocated chunk of memory.  This is important because
 * putenv() will leak otherwise (and setenv isn't thread safe)
 */
#define GDM_PAM_EXTENSION_ADVERTISE_SUPPORTED_EXTENSIONS(environment_block, supported_extensions) \
{ \
        size_t _size = 0; \
        unsigned char _t, _num_chunks; \
        char *_p; \
        _p = environment_block; \
        _p = stpncpy (_p, "GDM_SUPPORTED_PAM_EXTENSIONS", sizeof(environment_block)); \
        *_p = '\0'; \
        _size += strlen (environment_block); \
        for (_t = 0; supported_extensions[_t] != NULL && _t < UCHAR_MAX; _t++) {\
                size_t _next_chunk = strlen (supported_extensions[_t]) + strlen (" "); \
                if (_size + _next_chunk >= sizeof (environment_block)) \
                        break; \
                _size += _next_chunk; \
        }\
        _num_chunks = _t; \
        if (_t != 0) { \
                _p = stpcpy (_p, "="); \
                for (_t = 0; _t < _num_chunks; _t++) { \
                        if (_t != 0) \
                                _p = stpcpy (_p, " "); \
                        _p = stpcpy (_p, supported_extensions[_t]); \
                } \
                *_p = '\0'; \
                putenv (environment_block); \
        } \
}

#define GDM_PAM_EXTENSION_LOOK_UP_TYPE(name, extension_type) \
({ \
        bool _supported = false; \
        unsigned char _t = 0; \
        const char *_supported_extensions; \
        size_t _name_length; \
        _name_length = strcspn (name, " "); \
        _supported_extensions = getenv ("GDM_SUPPORTED_PAM_EXTENSIONS"); \
        if (_supported_extensions != NULL) { \
                const char *_p = _supported_extensions; \
                while (*_p != '\0') { \
                        size_t _length; \
                        _length = strcspn (_p, " "); \
                        if (_name_length == _length && strncmp (_p, name, _length) == 0) { \
                                _supported = true; \
                                break; \
                        } \
                        _p += _length; \
                        _length = strspn (_p, " "); \
                        _p += _length; \
                        if (_t >= UCHAR_MAX) { \
                                break; \
                        } \
                        _t++; \
                } \
                if (_supported && extension_type != NULL) \
                        *extension_type = _t; \
        } \
        _supported; \
})

#define GDM_PAM_EXTENSION_SUPPORTED(name) GDM_PAM_EXTENSION_LOOK_UP_TYPE(name, (unsigned char *) NULL)

#endif
