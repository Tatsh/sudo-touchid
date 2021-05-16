#include <config.h>

#ifdef HAVE_TOUCH_ID

#include <crt_externs.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include "sudoers.h"
#include "sudo_auth.h"

static const LAPolicy kAuthPolicy = 0x3f0;
static BOOL is_over_ssh = NO;

typedef enum {
    kTouchIDResultNone,
    kTouchIDResultAllowed,
    kTouchIDResultFailed
} TouchIDResult;

int
touchid_setup(struct passwd *pw, char **prompt, sudo_auth *auth)
{
    // If over SSH, indicated by non-empty environment variable SSH_CONNECTION,
    // fallback to PAM by exiting early as possible here
    // Still has to be AUTH_SUCCESS but is_over_ssh is set to non-zero
    char **ep, **envp = *_NSGetEnviron();
    const char *name = "SSH_CONNECTION";
    size_t namelen = 0;
    while (name[namelen] != '\0') {
        namelen++;
    }
    for (ep = envp; *ep != NULL; ep++) {
        if (strncmp(*ep, name, namelen) == 0 && (*ep)[namelen] == '=') {
            log_warningx(SLOG_SEND_MAIL, N_("No Touch ID over SSH."));
            is_over_ssh = 1;
            return AUTH_SUCCESS;
        }
    }
    @try {
        LAContext *context = [[LAContext alloc] init];
        BOOL canAuthenticate = [context canEvaluatePolicy:kAuthPolicy error:nil];
        [context release];
        if (canAuthenticate) {
            return AUTH_SUCCESS;
        }
    }
    @catch(NSException *) {
        // LAPolicyDeviceOwnerAuthenticationWithBiometrics may not be available on builds older than 10.12.1!
        sudo_printf(SUDO_CONV_INFO_MSG, _("2"));
    }
    audit_failure(NewArgv, "%s", N_("Touch ID setup failed."));
    return AUTH_FAILURE;
}

int
touchid_verify(struct passwd *pw, char *pass, sudo_auth *auth, struct sudo_conv_callback *callback)
{
    if (is_over_ssh) {
        return sudo_pam_verify(pw, pass, auth, callback);
    }
    LAContext *context = [[LAContext alloc] init];
    __block TouchIDResult result = kTouchIDResultNone;
    [context evaluatePolicy:kAuthPolicy localizedReason:@"authenticate a privileged operation" reply:^(BOOL success, NSError *error) {
        result = success ? kTouchIDResultAllowed : kTouchIDResultFailed;
        CFRunLoopWakeUp(CFRunLoopGetCurrent());
    }];
    while (result == kTouchIDResultNone)
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
    [context release];
    return result == kTouchIDResultAllowed ? AUTH_SUCCESS : AUTH_FAILURE;
}

int
touchid_pam_begin_session(struct passwd *pw, char **user_envp[], sudo_auth *auth)
{
    if (is_over_ssh) {
        return sudo_pam_begin_session(pw, user_envp, auth);
    }
    return AUTH_SUCCESS;
}

int
touchid_pam_end_session(struct passwd *pw, sudo_auth *auth)
{
    if (is_over_ssh) {
        return sudo_pam_end_session(pw, auth);
    }
    return AUTH_SUCCESS;
}
#endif // HAVE_TOUCH_ID
