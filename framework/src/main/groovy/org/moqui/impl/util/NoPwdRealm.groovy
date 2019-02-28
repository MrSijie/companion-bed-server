package org.moqui.impl.util

import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SaltedAuthenticationInfo
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.util.SimpleByteSource
import org.moqui.entity.EntityValue
import org.moqui.impl.context.ExecutionContextImpl

class NoPwdRealm extends MoquiShiroRealm {

    @Override
    AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        ExecutionContextImpl eci = ecfi.getEci()
        String username = token.principal as String
        String userId = null
        boolean successful = false
        boolean isForceLogin = token instanceof ForceLoginToken

        SaltedAuthenticationInfo info = null
        try {
            EntityValue newUserAccount = loginPrePassword(eci, username)
            userId = newUserAccount.getString("userId")

            // create the salted SimpleAuthenticationInfo object

            info = new SimpleAuthenticationInfo(username, newUserAccount.currentPassword,
                    newUserAccount.passwordSalt ? new SimpleByteSource((String) newUserAccount.passwordSalt) : null,
                    realmName)

            loginPostPassword(eci, newUserAccount)

            // at this point the user is successfully authenticated
            successful = true
        } finally {
            boolean saveHistory = true
            if (isForceLogin) {
                ForceLoginToken flt = (ForceLoginToken) token
                saveHistory = flt.saveHistory
            }
            if (saveHistory) loginAfterAlways(eci, userId, token.credentials as String, successful)
        }

        return info
    }

}
