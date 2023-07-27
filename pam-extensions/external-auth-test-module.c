#include <unistd.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#ifndef GDM_IN_TREE_BUILD
#include <gdm/gdm-pam-extensions.h>
#else
#include "gdm-pam-extensions.h"
#endif

int
pam_sm_authenticate (pam_handle_t  *pamh,
                     int            flags,
                     int            argc,
                     const char   **argv)
{
        int retval = PAM_ABORT;

        struct pam_conv *conversation_closure;
        struct pam_message prompt_message;
        const struct pam_message *prompt_messages[1];
        struct pam_response *reply = NULL;
        const char *external_auth_extension = GDM_PAM_EXTENSION_EXTERNAL_AUTH;

        GdmPamExtensionExternalAuthStartRequest *start_request = NULL;
        GdmPamExtensionExternalAuthStartResponse *start_response = NULL;
        GdmPamExtensionExternalAuthDisplayLinkRequest *display_link_request = NULL;
        GdmPamExtensionExternalAuthDisplayLinkResponse *display_link_response = NULL;

        if (!GDM_PAM_EXTENSION_SUPPORTED (GDM_PAM_EXTENSION_EXTERNAL_AUTH))
                goto out;

        retval = pam_get_item (pamh, PAM_CONV, (const void **) &conversation_closure);

        if (retval != PAM_SUCCESS)
                goto out;

        start_request = malloc (GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST_SIZE);
        GDM_PAM_EXTENSION_EXTERNAL_AUTH_START_REQUEST_INIT (start_request,
                                                            "Continue to initiate Web Login and "
                                                            "authenticate with an external device.");

        GDM_PAM_EXTENSION_MESSAGE_TO_BINARY_PROMPT_MESSAGE (start_request, &prompt_message);
        prompt_messages[0] = &prompt_message;

        retval = conversation_closure->conv (1, prompt_messages, &reply, conversation_closure->appdata_ptr);

        if (retval != PAM_SUCCESS)
                goto out;

        retval = PAM_ABORT;
        start_response = GDM_PAM_EXTENSION_REPLY_TO_EXTERNAL_AUTH_START_RESPONSE (reply);

        display_link_request = malloc (GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST_SIZE);
        GDM_PAM_EXTENSION_EXTERNAL_AUTH_DISPLAY_LINK_REQUEST_INIT (display_link_request,
                                                                   "Web Login",
                                                                   "short.url.com/1234",
                                                                   "1234")

        GDM_PAM_EXTENSION_MESSAGE_TO_BINARY_PROMPT_MESSAGE (display_link_request, &prompt_message);
        prompt_messages[0] = &prompt_message;

        retval = conversation_closure->conv (1, prompt_messages, &reply, conversation_closure->appdata_ptr);
        if (retval != PAM_SUCCESS)
                goto out;

        display_link_response = GDM_PAM_EXTENSION_REPLY_TO_EXTERNAL_AUTH_DISPLAY_LINK_RESPONSE (reply);
        sleep (2);

out:
        free (start_request);
        free (start_response);
        free (display_link_request);
        free (display_link_response);

        return retval;
}

int
pam_sm_setcred (pam_handle_t *pamh,
                int           flags,
                int           argc,
                const char  **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt (pam_handle_t  *pamh,
                  int            flags,
                  int            argc,
                  const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_chauthtok (pam_handle_t  *pamh,
                  int            flags,
                  int            argc,
                  const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_open_session (pam_handle_t  *pamh,
                     int            flags,
                     int            argc,
                     const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_close_session (pam_handle_t  *pamh,
                      int            flags,
                      int            argc,
                      const char   **argv)
{
        return PAM_SUCCESS;
}
