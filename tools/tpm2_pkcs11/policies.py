# These are the policy constants

#
# POLICY TYPES
#
NO_POLICY_TYPE = 0
USER_PIN_POLICY_TYPE = 1
SEAL_OBJECT_POLICY_TYPE = 1
USER_OBJECT_POLICY_TYPE = 2
SO_PIN_POLICY_SECRET_TYPE = 3

def set_user_object_policy(tpm2, userpinnvindex, userpin):
    session_context = tpm2.startauthsession(False)
    #PolicySecret(=sopin NV Index)
    user_object_policy, session_context = tpm2.policysecret(userpinnvindex, userpin, session_context)
    tpm2.flushsession(session_context)
    return user_object_policy

def set_userpin_with_sopin(tpm2, sopinnvindex, sopin, is_policy_session):
    session_context = tpm2.startauthsession(is_policy_session)
    _, session_context = tpm2.policysecret(sopinnvindex, sopin, session_context)
    #PolicySecret(=sopin NV Index)_AND_PolicyCommandCode(=TPM2_NV_ChangeAuth)
    user_pin_policy_truthvalue2, session_context = tpm2.policycommandcode("TPM2_CC_NV_ChangeAuth", session_context)
    if is_policy_session == False:
        tpm2.flushsession(session_context)
        return user_pin_policy_truthvalue2, None
    else:
        return user_pin_policy_truthvalue2, session_context

def set_pinauthobject_auth_with_pinobjectauth(tpm2, is_policy_session):
    session_context = tpm2.startauthsession(is_policy_session)
    _, session_context = tpm2.createpolicypassword(session_context)
    #PolicyPassword_AND_PolicyCommandCode(=TPM2_NV_ChangeAuth)
    user_pin_policy_truthvalue1, session_context = tpm2.policycommandcode("TPM2_CC_NV_ChangeAuth", session_context)
    if is_policy_session == False:
        tpm2.flushsession(session_context)
        return user_pin_policy_truthvalue1, None
    else:
        return user_pin_policy_truthvalue1, session_context
