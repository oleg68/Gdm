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
#ifndef GDM_EXTERNAL_AUTH_PAM_EXTENSION_H
#define GDM_EXTERNAL_AUTH_PAM_EXTENSION_H

#include "gdm-pam-extensions-common.h"

typedef struct {
        GdmPamExtensionMessage header;
        char *message;
} GdmPamExtensionExternalAuthStartRequest;

typedef struct {
        GdmPamExtensionMessage header;
} GdmPamExtensionExternalAuthStartResponse;

typedef struct {
        GdmPamExtensionMessage header;
        char *message;
        char *uri;
        char *code;
} GdmPamExtensionExternalAuthDisplayLinkRequest;

typedef struct {
        GdmPamExtensionMessage header;
} GdmPamExtensionExternalAuthDisplayLinkResponse;

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_PREFIX "org.gnome.DisplayManager.UserVerifier.ExternalAuth"

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH GDM_PAM_EXTENSION_DEFINE_TYPES(GDM_PAM_EXTENSION_EXTERNAL_AUTH_PREFIX, "StartRequest", "StartResponse", "DisplayLinkRequest", "DisplayLinkResponse")

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_TYPE(type) (GDM_PAM_EXTENSION_EXTERNAL_AUTH_PREFIX "." type)

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST GDM_PAM_EXTENSION_EXTERNAL_AUTH_TYPE("StartRequest")
#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST_SIZE (sizeof (GdmPamExtensionExternalAuthStartRequest))

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST_INIT(_request, _title) \
{ \
        GDM_PAM_EXTENSION_LOOK_UP_TYPE (GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST, &_request->header.type); \
        _request->header.length = htobe32 (GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST_SIZE); \
        _request->message = _title; \
}

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_RESPONSE GDM_PAM_EXTENSION_EXTERNAL_AUTH_TYPE("StartResponse")
#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_RESPONSE_SIZE sizeof (GdmPamExtensionExternalAuthStartResponse)
#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_RESPONSE_INIT(response) \
{ \
        GDM_PAM_EXTENSION_LOOK_UP_TYPE (GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_RESPONSE, &response->header.type); \
        response->header.length = htobe32 (GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_RESPONSE_SIZE); \
}
#define GDM_PAM_EXTENSION_REPLY_TO_EXTERNAL_AUTH_START_RESPONSE(reply) ((GdmPamExtensionExternalAuthStartResponse *) (void *) reply->resp)

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST GDM_PAM_EXTENSION_EXTERNAL_AUTH_TYPE("DisplayLinkRequest")
#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST_SIZE (sizeof (GdmPamExtensionExternalAuthDisplayLinkRequest))

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST_INIT(_request, _message, _uri, _code) \
{ \
        GDM_PAM_EXTENSION_LOOK_UP_TYPE (GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST, &_request->header.type); \
        _request->header.length = htobe32 (GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST_SIZE); \
        _request->message = _message; \
        _request->uri = _uri; \
        _request->code = _code; \
}

#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE GDM_PAM_EXTENSION_EXTERNAL_AUTH_TYPE("DisplayLinkResponse")
#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE_SIZE sizeof (GdmPamExtensionExternalAuthDisplayLinkResponse)
#define GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE_INIT(response) \
{ \
        GDM_PAM_EXTENSION_LOOK_UP_TYPE (GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE, &response->header.type); \
        response->header.length = htobe32 (GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE_SIZE); \
}
#define GDM_PAM_EXTENSION_REPLY_TO_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE(reply) ((GdmPamExtensionExternalAuthDisplayLinkResponse *) (void *) reply->resp)


#endif
