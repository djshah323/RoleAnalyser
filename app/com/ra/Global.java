/**
 * 
 */
package com.ra;

import com.ra.ldap.LDAPInterface;

import play.Application;
import play.GlobalSettings;
import play.Play;

/**
 * @author SDhaval
 *
 */
public class Global extends GlobalSettings
{

    static LDAPInterface m_ldapConnection;
    private static String m_baseContainer;
    
    @Override
    public void onStart(Application arg0) {

        
        String host = Play.application().configuration().getString("eDirHostName", "localhost");
        int clearPort = Play.application().configuration().getInt("eDirClearTextPort", 389);
        int sslPort = Play.application().configuration().getInt("eDirSSLPort", 636);
        boolean useSSL = Play.application().configuration().getBoolean("eDirUseSSL", false);
        m_ldapConnection = new LDAPInterface(host,clearPort,sslPort,useSSL);
        m_ldapConnection.connectToLDAP();
        m_baseContainer = Play.application().configuration().getString("eDirBaseContainer", "o=data");
        super.onStart(arg0);
    }
    
}
