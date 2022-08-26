package com.ra.ldap;


import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;


import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.Base64;
import com.novell.ldap.util.LDIFReader;
import com.novell.ldap.util.LDIFWriter;



/*
 * TODO: Things that can be done here,
 * 1. provide a function which will automatically convert something like admin.novell into cn=admin, o=novell
 *     We need a generic function to convert the dot format to comma separated format. Possibly we can pass the String and return String
 * 2. how do i pass the information whether the channel is secure or not?
 * 3. Should we have some functionality to handle the events? this can be extended by the DSTrace portion?
 */


/*
 * Replacing "searchResults.hasMore()" with "isConnected() && searchResults.hasMore()" because the function goes into infinite loop
 * waiting for the results when the connection could not be established.
 */

public class LDAPInterface
{
   private LDAPConnection m_connection  = null;
   private int            m_ldapVersion = LDAPConnection.LDAP_V3;
   private String         m_host;
   private int            m_port;
   private String         m_userName;
   private String         m_password;
   private int            m_timeout=5000; 
   private int            m_ldapClearPort=389;
   private int            m_ldapSecurePort=636;
   private boolean        m_useSecurePort=false;
   
   //AccessNDSMessages.
   public static String   LDIF_VERSION_STRING            = "version: 1"; //$NON-NLS-1$
   public static String   NAMING_ATTRIBUTE_ERROR = "NDS error: cant remove naming value (-627)";//$NON-NLS-1$
   public static final String EOL                    = "\r\n";                                      //$NON-NLS-1$ 
   public static final String SPACE = " ";//$NON-NLS-1$
   public static final String SPACE_COLON = " : ";//$NON-NLS-1$
   public static final String DN_TYPE_DOT = "dot"; //$NON-NLS-1$
   public static final String DN_TYPE_LDAP = "ldap"; //$NON-NLS-1$
   public static final String ENTRY_ALREADY_EXISTS_MESSAGE = "Entry Already Exists"; //$NON-NLS-1$
   // Use default port 389 for the LDAP
   public LDAPInterface(
      String host,
      String userName,
      String password )
   {
      if (JavaUtil.hasString( host ) && host.indexOf( ":" ) != -1) //$NON-NLS-1$
      {
         m_host = host.substring( 0, host.indexOf( ":" )  //$NON-NLS-1$
                                   );
      }
      else
         m_host = host;
      m_userName = userName;
      m_password = password;
//      m_port = 636;// The default port used in DSTrace is also 636
   }

   //If a user specifies the port
   public LDAPInterface(
      String host,
      String userName,
      String password,
      int port )
   {
      this(host,userName,password);
      m_port = port;
   }
   
   public LDAPInterface(
      String host,
      String userName,
      String password,
      int ldapClearTextPort,
      int ldapSecurePort,
      boolean useSecurePort)
   {
      this(host,userName,password);
      m_ldapClearPort = ldapClearTextPort;
      m_ldapSecurePort = ldapSecurePort;
      m_useSecurePort = useSecurePort;
   }
   
   public LDAPInterface(
      String host,
      int ldapClearTextPort,
      int ldapSecurePort,
      boolean useSecurePort)
   {
	   this(host,"","");
	   m_ldapClearPort = ldapClearTextPort;
	   m_ldapSecurePort = ldapSecurePort;
	   m_useSecurePort = useSecurePort;
   }

   // presently only unsecure communication occurs.
   // We can setup the secure communication channel but how do we pass that information from the DSAccess Object
   // Method not to be exposed to the outside world hence private
   // is there a need for secure communication?
   private void initConnection()
         throws Exception
   {
      if (m_useSecurePort)
      {
         Security.addProvider( new com.sun.net.ssl.internal.ssl.Provider() );
         TrustManager[] tms =
         {new LDAPTrustManager()};
         SSLContext context = SSLContext.getInstance( "TLS", "SunJSSE" );//$NON-NLS-1$ //$NON-NLS-2$
         context.init( null,
                       tms,
                       null );
         LDAPJSSESecureSocketFactory ssf = new LDAPJSSESecureSocketFactory(
               context.getSocketFactory() );
         m_connection = new LDAPConnection( ssf);
      }else{
         m_connection = new LDAPConnection(m_timeout);
      }
   }
   

   // sets up a new LDAP connection
   // It is not clear when will this DSAccess Object set up an LDAP channel
   // DSAccess only stores the credentials used to connect to eDirectory
   // So when should setting up of the LDAP channel takes place?
   public void connectToLDAP()
   {
      try
      {

         if(m_useSecurePort){
            m_port = m_ldapSecurePort;
         }else{
            m_port = m_ldapClearPort;
         }
         // init the connection only when m_connection is not established.
         // This is to avoid initialization of new object if a given connection gets timed out
         if (null == m_connection)
         {
            initConnection();
         }
         // connect to the server
         m_connection.connect( m_host,
                               m_port );

         // authenticate to the server
//         m_connection.bind( m_ldapVersion,
//                            m_userName,
//                            m_password.getBytes( "UTF8" ) );//$NON-NLS-1$
      }
      catch (LDAPException e)
      {
         // Need to keep a log of why the LDAP connection could not be established.
 
      }
      catch (UnsupportedEncodingException e)
      {
       }
      catch (Exception e)
      {
       }
   }
   
   public void bind(String userName, String password)
   {
	   if (m_connection != null)
	   {
         try {
			m_connection.bind( m_ldapVersion,
			 userName,
			 password.getBytes( "UTF8" ) );
			
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (LDAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}//$NON-NLS-1$
	   }
   }
   
   // sets up a new LDAP connection
   // It is not clear when will this DSAccess Object set up an LDAP channel
   // DSAccess only stores the credentials used to connect to eDirectory
   // So when should setting up of the LDAP channel takes place?
   public void connectToLDAP(String errrorMessage)
   {
      try
      {

         // init the connection only when m_connection is not established.
         // This is to avoid initialization of new object if a given connection gets timed out
         if(m_useSecurePort){
            m_port = m_ldapSecurePort;
         }else{
            m_port = m_ldapClearPort;
         }
         if (null == m_connection)
         {
            initConnection();
         }

         // connect to the server
         m_connection.connect( m_host,
                               m_port );

         // authenticate to the server
         m_connection.bind( m_ldapVersion,
                            m_userName,
                            m_password.getBytes( "UTF8" ) );//$NON-NLS-1$
      }
      catch (LDAPException e)
      {
       e.printStackTrace();
 
      }
      catch (UnsupportedEncodingException e)
      {   
         e.printStackTrace();
       }
      catch (Exception e)
      {   e.printStackTrace();
       }
   }

////   For test purposes
//   public static void main(
//      String agrs[] )
//   {
//      LDAPConnectionObject object = new LDAPConnectionObject(
//            "164.99.90.236",
//            "cn=admin,o=novell",
//            "novell" );
//      object.connectToLDAP();
//      System.out.println( object.isConnected() );
////      String searchFilter = "cn=*";
//      String searchAttrib = "memberQueryURL";
//      object.disconnect();
//      List<String> dataRetrived = object.getAttribute( "cn=ttt,cn=Entitlement Policies,cn=Chendil-DriverSet2,o=novell", null, searchAttrib );
////      List<String> dataRetrived = object.getAttribute( "o=novell",
////                                                       searchFilter,
////                                                       searchAttrib );
//
//      object.updateAttribute( "cn=ttt,cn=Entitlement Policies,cn=Chendil-DriverSet2,o=novell",
//                              searchAttrib,
//                              "ldap:///??sub?(&(ou=User)(objectClass=inetOrgPerson))?x-sparse" );
//      
//      object.disconnect();
//      System.out.println( dataRetrived.size() );
//      for (int i = 0; i < dataRetrived.size(); i++)
//         System.out.println( dataRetrived.get( i ) );
//
//
//      System.out.println( object.isConnected() );
//
//   }

   // This is used to disconnect the already setup LDAP channel
   public void disconnect()
   {
      if (null != m_connection)
      {
         try
         {
            m_connection.disconnect();
         }
         catch (LDAPException e)
         {
            e.printStackTrace();
         }
      }
   }

   // Presently the SearchResult is only working for memberQueryURL
   // We can extend it to retrieve it for attributes other than memberQueryUrl
   // The attributes that need to be searched are passed in as searchAttrib
   // if we want to search memberQueryURL we want searchAttrib = "memberQueryURL" 
   //searchFilter
   public List<String> getAttribute(
      String searchBase,
      String searchFilter,
      String searchAttrib )
   {
      List<String> result = new ArrayList<String>();
      if (!(null == m_connection))
      {
         // If LDAPconnection was closed or timed out it was getting stuck in the while loop
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            String searchAttribute[] = new String[1];
            searchAttribute[0] = searchAttrib;

            LDAPSearchResults searchResults = m_connection.search( searchBase,
                                                                   LDAPConnection.SCOPE_BASE,
                                                                   searchFilter,
                                                                   searchAttribute,
                                                                   false );
            
            while (isConnected() && searchResults.hasMore())
            {
               LDAPEntry nextEntry = null;

               try
               {

                  nextEntry = searchResults.next();

               }

               catch (LDAPException e)
               {

                  // Exception is thrown, go for next entry

                 // Log.error(AccessNDSMessages.ATTRIBUTE_RETREIVAL_ERROR,e);
                  if (e.getResultCode() == LDAPException.LDAP_TIMEOUT
                        || e.getResultCode() == LDAPException.CONNECT_ERROR)

                     break;

                  else

                     continue;

               }



               LDAPAttributeSet attributeSet = nextEntry.getAttributeSet();

               Iterator allAttributes = attributeSet.iterator();



               while (allAttributes.hasNext())
               {

                  LDAPAttribute attribute =

                  (LDAPAttribute) allAttributes.next();


                  Enumeration allValues = attribute.getStringValues();

                  if (allValues != null)
                  {

                     while (allValues.hasMoreElements())
                     {

                        String Value = (String) allValues.nextElement();

                        if (Base64.isLDIFSafe( Value ))
                        {
                           result.add( Value );
                        }

                        else
                        {
                           Value = Base64.encode( Value.getBytes() );

                           result.add( Value );

                        }

                     }

                  }

               }
            }

         }
         catch (LDAPException e)
         {
            e.printStackTrace();// Log.error(AccessNDSMessages.ATTRIBUTE_RETREIVAL_ERROR,e);
          }
         catch (Exception e)
         {
            e.printStackTrace();// Log.error(AccessNDSMessages.ATTRIBUTE_RETREIVAL_ERROR,e);
          }

      }
      return result;
   }


   // This allows a user to retrieve the specific attribute with the given search scope

   public List<String> getAttribute(
      String searchBase,
      String searchFilter,
      String searchAttrib,
      int searchScope )
   {
      List<String> result = new ArrayList<String>();
      if (!(null == m_connection))
      {
         // If LDAPconnection was closed or timed out it was getting stuck in the while loop
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");//AccessNDSMessages.ATTRIBUTE_RETREIVAL_ERROR);
         }
            try
            {
               String searchAttribute[] = new String[1];
               searchAttribute[0] = searchAttrib;
               LDAPSearchResults searchResults;
             
             
                  searchResults = m_connection.search( searchBase,
                                                       searchScope,
                                                       searchFilter,
                                                       searchAttribute,
                                                       false );
             
               while (isConnected() && searchResults.hasMore())
               {
                  LDAPEntry nextEntry = null;

                  try
                  {

                     nextEntry = searchResults.next();

                  }

                  catch (LDAPException e)
                  {
                     // Exception is thrown, go for next entry
                     //Log.error(AccessNDSMessages.ATTRIBUTE_RETREIVAL_ERROR,e);
                	  e.printStackTrace();

                     if (e.getResultCode() == LDAPException.LDAP_TIMEOUT
                           || e.getResultCode() == LDAPException.CONNECT_ERROR)

                        break;

                     else

                        continue;

                  }

                  LDAPAttributeSet attributeSet = nextEntry.getAttributeSet();

                  Iterator allAttributes = attributeSet.iterator();

                  while (allAttributes.hasNext())
                  {

                     LDAPAttribute attribute =

                     (LDAPAttribute) allAttributes.next();

                     Enumeration allValues = attribute.getStringValues();

                     if (allValues != null)
                     {
                        while (allValues.hasMoreElements())
                        {
                           String Value = (String) allValues.nextElement();
                           if (Base64.isLDIFSafe( Value ))
                           {
                              result.add( Value );
                           }
                           else
                           {

                              // base64 encode 
                              Value = Base64.encode( Value.getBytes() );
                              result.add( Value );
                           }
                        }
                     }
                  }
               }

            }
            catch (LDAPException e)
            {
                e.printStackTrace();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
         }
      
      return result;
   }
   
   // Presently the SearchResult is only working for memberQueryURL
   // We can extend it to retrieve it for attributes other than memberQueryUrl
   // The attributes that need to be searched are passed in as searchAttrib
   // if we want to search memberQueryURL we want searchAttrib = "memberQueryURL" 
   //searchFilter
   public String getObject(
      String searchBase,
      String searchFilter,
      String searchAttrib )
   {
      String result = null;
      if (!(null == m_connection))
      {
         // If LDAPconnection was closed or timed out it was getting stuck in the while loop
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            String searchAttribute[] = new String[1];
            searchAttribute[0] = searchAttrib;

            LDAPSearchResults searchResults = m_connection.search( searchBase,
                                                                   LDAPConnection.SCOPE_SUB,
                                                                   searchFilter,
                                                                   null,
                                                                   false );

            ByteArrayOutputStream out = new ByteArrayOutputStream();


            LDIFWriter writer = new LDIFWriter( out );

            
            while (isConnected() && searchResults.hasMore())
            {
                LDAPEntry ldapEntry=null;
                ldapEntry = searchResults.next();
               try {
                   writer.writeEntry( ldapEntry );
               }  catch (IOException e) {
                //Log.error(AccessNDSMessages.ERROR_WRITING_OBJECT_TO_LDIF,e);
            	   e.printStackTrace();
               }
               
            }

            writer.finish();
            out.close();
            return out.toString();
            

         }
         catch (LDAPException e)
         {
           e.printStackTrace();
         }
         catch (Exception e)
         {
            e.printStackTrace();
         }

      }
      return result;
   }
   
   public static String stripOutVersionStrings(
      String ldifData )
   {
      InputStream in = new ByteArrayInputStream( ldifData.getBytes() );

      BufferedReader br = new BufferedReader( new InputStreamReader( in ) );
      String line;
      StringBuilder stringBuilder = new StringBuilder();
      boolean firstOccurence = true;
      try
      {
         while ((line = br.readLine()) != null)
         {

            if (line.trim().equals( LDIF_VERSION_STRING ) )
            {
               if (firstOccurence)
               {
                  stringBuilder.append( line );
                  firstOccurence = false;
               }
               
            }
            else 
               stringBuilder.append( line );
               
            
            stringBuilder.append( System.getProperty( "line.separator" ) ); //$NON-NLS-1$
         }
         br.close();
      }
      catch (IOException e)
      {

      }
      return stringBuilder.toString();

   }
//   public static void main(
//      String agrs[] )
//   {
//      
//      int scope = LDAPConnection.SCOPE_SUB;
//      LDAPConnectionObject object = new LDAPConnectionObject(
//            "164.99.136.172",
//            "cn=admin,o=novell",
//            "novell" );
//      object.connectToLDAP();
//      System.out.println( object.isConnected() );
//      String searchFilter = "cn=*";
//      String searchAttrib = "memberQueryURL";
//      String searchAttribute[] = new String[1];
//      searchAttribute[0] = searchAttrib;//$NON-NLS-1$
////      object.updateObjects("");
//      object.connectToLDAP();
//      try
//      {
//         LDAPSearchResults searchResults = object.m_connection.search( "o=novell",
//                                                                LDAPConnection.SCOPE_SUB,
//                                                                searchFilter,
//                                                                null,
//                                                                false );
//         while (searchResults.hasMore())
//         {
//            LDAPEntry ldapEntry = searchResults.next();
//            System.out.println(ldapEntry.getDN());
//         }
//      }
//      catch (LDAPException e)
//      {
//         // TODO Auto-generated catch block
//         e.printStackTrace();
//      }
//      
////            List<String> dataRetrived = object.getAttribute( "cn=Entitlement Policies,cn=Chendil-DriverSet2,o=novell", searchFilter, searchAttrib );
////      List<String> dataRetrived = object.getAttribute( "o=novell",
////                                                       searchFilter,
////                                                       searchAttrib );
//
////      object.writeToFileLDIF(
////         "cn=Entitlement Policies,cn=Chendil-DriverSet2,o=novell",
////                              searchFilter,
////                              searchAttribute,
////         scope );
////      object.updateAttribute( "cn=Entitlement Policies,cn=Chendil-DriverSet2,o=novell",
////                              searchAttrib,
////                              "ldap:///??sub?(&(ou=Person)(objectClass=inetOrgPerson))?x-sparse" );
//      object.disconnect();
////      System.out.println( dataRetrived.size() );
////      for (int i = 0; i < dataRetrived.size(); i++)
////         System.out.println( dataRetrived.get( i ) );
//
//
//      
//
//      System.out.println( object.isConnected() );
//
//   }
   // Presently the SearchResult is only working for memberQueryURL
   // We can extend it to retrieve it for attributes other than memberQueryUrl
   // The attributes that need to be searched are passed in as searchAttrib
   // if we want to search memberQueryURL we want searchAttrib = "memberQueryURL" 
   //searchFilter
   public String getObjects(
      List<String> objects,
      String searchFilter,
      String searchAttrib)
   {
      String result = null;
      if (!(null == m_connection))
      {
         // If LDAPconnection was closed or timed out it was getting stuck in the while loop
         if (!m_connection.isConnected())
         {  
            for(String object: objects)
               connectIfNotConnected("");
         }
         try
         {

            if (objects != null && objects.size() > 0)
            {
               ByteArrayOutputStream out = new ByteArrayOutputStream();
               for (String object : objects)
               {
                  LDAPEntry ldapEntry=null;
                  try
                  {
                     LDAPSearchResults searchResults = m_connection.search( object,
                                                                            LDAPConnection.SCOPE_BASE,
                                                                            searchFilter,
                                                                            null,
                                                                            false );
                     LDIFWriter writer = new LDIFWriter( out );

                     while (isConnected() && searchResults.hasMore())
                     {
                        ldapEntry = searchResults.next();
                        writer.writeEntry( ldapEntry );
                        //statusResults.add(new StatusResult(ldapEntry.getDN(),StatusResult.SEVERITY_INFO,AccessNDSMessages.OBJECT_ADDED_IN_LDIF,null));
                     }
                     writer.finish();
                  }
                  catch (LDAPException e)
                  {       
                	  e.printStackTrace();
                     //statusResults.add(new StatusResult(AccessNDSMessages.WRITING_TO_FILE_INTERRUPTED,StatusResult.SEVERITY_ERROR,AccessNDSMessages.OBJECT_NOT_RETREIVED,e));
                  }
                  catch (Exception e)
                  {
                	  e.printStackTrace();
                     //statusResults.add(new StatusResult(AccessNDSMessages.WRITING_TO_FILE_INTERRUPTED,StatusResult.SEVERITY_ERROR,AccessNDSMessages.OBJECT_NOT_RETREIVED,e));
                  }


               }
               out.close();
               return stripOutVersionStrings(out.toString());
            }

         }
         catch (Exception e)
         {
           e.printStackTrace();// Log.error(AccessNDSMessages.OBJECT_NOT_RETREIVED,e);
         }


      }
      return result;
   }
   //======================================================================================================================================
   //======================================================================================================================================
   //======================================================================================================================================
   
  public List<User> getUsers (String searchBase, int scope, String searchFilter, String [] readFilter)
   {
	   List<LDAPEntry> entryList = getSCIMObjects(searchBase, scope, searchFilter, readFilter);
	   List<User> userList = new ArrayList<User>();
	   for (LDAPEntry entry : entryList) {
		   User usr = new User();
//		   String dn = entry.getDN();
//		   usr.setAttribute("dn", dn);
		   LDAPAttributeSet attrSet = entry.getAttributeSet();
		   Iterator iter = attrSet.iterator();
		   while (iter.hasNext()) {
			   LDAPAttribute attr = (LDAPAttribute) iter.next();
			   String name = attr.getName();
			   String value = JavaUtil.getStringArrayToString(attr.getStringValueArray());
			   usr.setAttribute(name, value.toString());
		   }
		   if (usr.getAttrCount() > 0) {
			   usr.setLink();
			   userList.add(usr);
		   }
	   }
	   return userList;
   }
   
   public List<Group> getGroups (String searchBase, int scope, String searchFilter, String [] readFilter)
   {
	   List<LDAPEntry> entryList = getSCIMObjects(searchBase, scope, searchFilter, readFilter);
	   List<Group> groupList = new ArrayList<Group>();
	   for (LDAPEntry entry : entryList) {
		   Group grp = new Group();
//		   String dn = entry.getDN();
//		   grp.setAttribute("dn", dn);
		   LDAPAttributeSet attrSet = entry.getAttributeSet();
		   Iterator iter = attrSet.iterator();
		   while (iter.hasNext()) {
			   LDAPAttribute attr = (LDAPAttribute) iter.next();
			   String name = attr.getName();
			   String value = JavaUtil.getStringArrayToString(attr.getStringValueArray());
			   grp.setAttribute(name, value);
		   }
		   if (grp.getAttrCount() > 0)
		   {
			   grp.setLink();
			   groupList.add(grp);
		   }
	   }
	   return groupList;
   }
   
   public List<LDAPEntry> getSCIMObjects(
		   String searchBase, 
		   int searchScope,
		   String searchFilter, 
		   String[] searchAttrib) 
   {
		connectIfNotConnected("");
		List<LDAPEntry> resultMap = new ArrayList<LDAPEntry>();
		
		if (!(null == m_connection)) {
			// If LDAPconnection was closed or timed out it was getting stuck in
			// the while loop
			
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			LDAPEntry ldapEntry = null;
			try {
				if (searchScope == -1) {
					searchScope = LDAPConnection.SCOPE_SUB;
				}
				
				LDAPSearchResults searchResults = m_connection.search(
						searchBase, searchScope, searchFilter,
						searchAttrib, false);

				while (isConnected() && searchResults.hasMore()) {
					ldapEntry = searchResults.next();
					resultMap.add(ldapEntry);
				}
			} catch (LDAPException e) {
				e.printStackTrace();
				// statusResults.add(new
				// StatusResult(AccessNDSMessages.WRITING_TO_FILE_INTERRUPTED,StatusResult.SEVERITY_ERROR,AccessNDSMessages.OBJECT_NOT_RETREIVED,e));
			} catch (Exception e) {
				e.printStackTrace();
				// statusResults.add(new
				// StatusResult(AccessNDSMessages.WRITING_TO_FILE_INTERRUPTED,StatusResult.SEVERITY_ERROR,AccessNDSMessages.OBJECT_NOT_RETREIVED,e));
			}
			try {
				out.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return resultMap;
	}
   
   public boolean addUser (User user, String context)
   {
	   user.setAttribute("objectclass", "inetOrgPerson");
	   Map<String,List<String>> attributes = new HashMap<String,List<String>>();
	   Set<String> keys = user.getKeySet();
	   String cn = null;
	   for (String attr : keys) {
		   String value = user.getAttribute(attr);
		   if (attr.equalsIgnoreCase("cn")) {
			   cn = value;
		   }
		   List<String> l = new ArrayList<String>();
		   l.add(value);
		   attributes.put(attr, l);
	   }
	   if (cn == null) {
		   cn = "" + System.currentTimeMillis();
	   }
	   return addSCIMObject("CN=" + cn + "," +context, attributes);
   }
   

   public boolean deleteSCIMObject(Long scimId, String base)
   {
	   
	   boolean result = true;
	   if (!(null == m_connection))
	      {
	         if (!m_connection.isConnected())
	         {
	            connectIfNotConnected("");
	         }
	         try
	         {
	        	 List<LDAPEntry> entryList = getSCIMObjects(base, LDAPConnection.SCOPE_SUB, "SCIM-Id=" + scimId, null);
	        	 if (entryList != null && entryList.size() > 0) {
	        		 m_connection.delete(entryList.get(0).getDN());
	        	 } else {
	        		 result = false;
	        	 }
	         }
	         catch (LDAPException e)
	         {
	        	 e.printStackTrace();
	            result = false;
	         }
	         catch (Exception e)
	         {
	        	 e.printStackTrace();
	            result = false;
	         }
	      }else{
	        result = false;
	      }
	      
	      return result;
   }

   public boolean addGroup (Group group, String context)
   {
	   group.setAttribute("objectclass", "groupOfNames");
	   Map<String,List<String>> attributes = new HashMap<String,List<String>>();
	   Set<String> keys = group.getKeySet();
	   String cn = null;
	   for (String attr : keys) {
		   String value = group.getAttribute(attr);
		   if (attr.equalsIgnoreCase("cn")) {
			   cn = value;
		   }
		   List<String> l = new ArrayList<String>();
		   l.add(value);
		   attributes.put(attr, l);
	   }
	   if (cn == null) {
		   cn = "" + System.currentTimeMillis();
	   }
	   return addSCIMObject("CN=" + cn + "," +context, attributes);
   }
   
   public boolean addSCIMObject (String context, Map<String,List<String>> attributes)
   {
      boolean result = true;
       
      LDAPAttributeSet attrSet = new LDAPAttributeSet();
      for (String attrCN : attributes.keySet())
      {
         List<String> values = attributes.get( attrCN );
         LDAPAttribute attribute = new LDAPAttribute( attrCN );
         
         for (String value:values)
            attribute.addValue( value );
         
         attrSet.add( attribute );
      }
      
      LDAPEntry entry = new LDAPEntry(context,attrSet);
            
      
      if (!(null == m_connection) && entry != null)
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            m_connection.add( entry );
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
   public boolean updateSCIMAttribute (String context, Group group, User user)
   {
	   String id = null;
	   int count = -1;
	   Set<String> keySet = null;
	   AbsSCIMObj obj = null;
	   if (user != null) {
		   id = user.getAttribute("SCIM-Id");
		   count = user.getAttrCount();
		   keySet = user.getKeySet();
		   obj = user;
	   } else {
		   id = group.getAttribute("SCIM-Id");
		   count = group.getAttrCount();
		   keySet = group.getKeySet();
		   obj = group;
	   }
	   keySet.remove("SCIM-Id");
			   
	   int scope = LDAPConnection.SCOPE_SUB;
	   String filter = "SCIM-Id=" + id;
	   String [] readFilter = null;
	   if (count <= 0)
	   {
		   return false;
	   }
	   readFilter = new String[keySet.size()];
	   int x = 0;
	   for (String s : keySet) {
		   readFilter[x++] = s;
	   }
	   List<LDAPEntry> entryList = getSCIMObjects(Global.getBaseContainer(), scope, filter, readFilter);
	   if (entryList != null && entryList.size() <= 0) {
		   System.out.println("No Matching object found with SCIM-Id : " + id);
		   return false;
	   }
	   LDAPEntry entry = entryList.get(0);
	   if (context == null) {
		   context = entry.getDN();
	   }
	   LDAPModification [] modArray = new LDAPModification[count - 1];
	   int i =0;
	   for (String attr : keySet) {
		   LDAPAttribute attribute = entry.getAttribute(attr);
		   if (attribute == null) {
			   attribute = new LDAPAttribute(attr);
		   }
		   String valStr = obj.getAttribute(attr);
		   if (valStr.indexOf(AbsSCIMObj.DELIM) != -1) {
			   StringTokenizer strtok = new StringTokenizer(valStr, AbsSCIMObj.DELIM);
			   while (strtok.hasMoreElements()) {
				   String t1 = strtok.nextToken();
				   attribute.addValue(t1);
			   }
		   } else {
			   attribute.addValue(valStr);
		   }
		   if (group != null && attr.equalsIgnoreCase("member")) {
			   // handle group members..
			   String [] scimIds = attribute.getStringValueArray();
			   List<LDAPEntry> memEntryList = getMembers(scimIds);
			   String [] attrList = new String[memEntryList.size()];
			   int j = 0;
			   for (LDAPEntry ent: memEntryList) {
				   String udn = ent.getDN();
				   LDAPAttribute gmem = ent.getAttribute("groupMembership");
				   if (gmem == null) {
					   gmem = new LDAPAttribute("groupMembership", context);
				   } else {
					   gmem.addValue(context);
				   }
				   LDAPModification umod = new LDAPModification(LDAPModification.REPLACE, gmem);
				   try
				   {
					   m_connection.modify(udn, umod);
				   }
				   catch (LDAPException e) {
					   e.printStackTrace();
				   }
				   attrList[j++] = udn;
			   }
			   attribute = new LDAPAttribute(attr, attrList);
		   }
		   LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attribute);
		   modArray[i++] = mod;
	   }
	   try
	   {
		   m_connection.modify(context, modArray);
		   return true;
	   }
	   catch (LDAPException e) {
		   e.printStackTrace();
		   return false;
	   }
   }
   
   private List<LDAPEntry> getMembers(String [] ids)
   {
	   StringBuilder sbuilder = new StringBuilder();
	   sbuilder.append("(|");
	   for (int i=0; i<ids.length; i++) {
		   sbuilder.append("(SCIM-Id=" + ids[i] + ")");
	   }
	   sbuilder.append(")");
	   int scope = LDAPConnection.SCOPE_SUB;
	   String filter = sbuilder.toString();
	   String [] readFilter = new String[] {"groupMembership"};
	   return getSCIMObjects(Global.getBaseContainer(), scope, filter, readFilter);
   }
   
   //======================================================================================================================================
   //======================================================================================================================================
   //======================================================================================================================================
   
   public String getObjects(
		      String searchBase,
		      String searchFilter,
		      String searchAttrib)
		   {
		  	return getObjects(searchBase, LDAPConnection.SCOPE_SUB, searchFilter, searchAttrib);
		   }
   
   
// Presently the SearchResult is only working for memberQueryURL
   // We can extend it to retrieve it for attributes other than memberQueryUrl
   // The attributes that need to be searched are passed in as searchAttrib
   // if we want to search memberQueryURL we want searchAttrib = "memberQueryURL" 
   //searchFilter
	public String getObjects(String searchBase, int searchScope,
			String searchFilter, String searchAttrib) {
		String result = null;
		connectIfNotConnected("");
		if (!(null == m_connection)) {
			// If LDAPconnection was closed or timed out it was getting stuck in
			// the while loop

			
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			LDAPEntry ldapEntry = null;
			try {
				if (searchScope == -1) {
					searchScope = LDAPConnection.SCOPE_SUB;
				}
				LDAPSearchResults searchResults = m_connection.search(
						searchBase, searchScope, searchFilter,
						null, false);
				LDIFWriter writer = new LDIFWriter(out);

				while (isConnected() && searchResults.hasMore()) {
					ldapEntry = searchResults.next();
					writer.writeEntry(ldapEntry);
					// statusResults.add(new
					// StatusResult(ldapEntry.getDN(),StatusResult.SEVERITY_INFO,AccessNDSMessages.OBJECT_ADDED_IN_LDIF,null));
				}
				writer.finish();
			} catch (LDAPException e) {
				e.printStackTrace();
				// statusResults.add(new
				// StatusResult(AccessNDSMessages.WRITING_TO_FILE_INTERRUPTED,StatusResult.SEVERITY_ERROR,AccessNDSMessages.OBJECT_NOT_RETREIVED,e));
			} catch (Exception e) {
				e.printStackTrace();
				// statusResults.add(new
				// StatusResult(AccessNDSMessages.WRITING_TO_FILE_INTERRUPTED,StatusResult.SEVERITY_ERROR,AccessNDSMessages.OBJECT_NOT_RETREIVED,e));
			}
			try {
				out.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return stripOutVersionStrings(out.toString());
		}

		return result;
	}
   
// This function uses replace attributes approach.
// public boolean updateObjects(
//    String ldifData )
// {
//    boolean result = true;
//    // If LDAPconnection was closed or timed out it was getting stuck in the while loop
//    if (!(null == m_connection))
//    {
//       if (!m_connection.isConnected())
//       {
//          connectIfNotConnected();
//       }
//       try
//       {
//          InputStream in = new ByteArrayInputStream( ldifData.getBytes() );
//
//
//          LDIFReader reader = new LDIFReader( in );
//
//          LDAPMessage mesg = null;
//          List res = new ArrayList();
//          LDAPEntry entry;
//          LDAPAttributeSet as;
//          Iterator allAttrs;
//          boolean flag;
//
//          while ((mesg = reader.readMessage()) != null)
//          {
//             entry = ((LDAPSearchResult)mesg).getEntry();
//             flag = true;
//             // It tries to add an object to the eDirectory 
//             // If the object is already present in the eDirectory then it will throw an exception
//             // It will try to replace the object.
//             try 
//             {
//                    m_connection.add(entry);                        
//                    flag = false;
//            } 
//             catch (LDAPException e)
//             {
//
//            }finally{
//                   if (flag) {
//                    as = entry.getAttributeSet();
//                    allAttrs = as.iterator();
//                    while (allAttrs.hasNext()) {
//                        m_connection.modify(entry.getDN(),
//                                new LDAPModification(
//                                        LDAPModification.REPLACE,
//                                        (LDAPAttribute) allAttrs.next()));
//                    }
//                }
//            }
//          }
//          return true;
//       }
//       catch (LDAPException e)
//       {
//          result = false;
//          disconnect();
//       }
//       catch (Exception e)
//       {
//          result = false;
//          disconnect();
//       }
//    }
//    else
//    {
//       result = false;
//    }
//
//    return result;
// }
   
   
   /*This function will try to add the object in the eDirectory
    * If the object already exists then the object will delete the object
    * and would add the object again in eDirectory. 
    */
   public boolean updateObjects(
      String ldifData )
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");//, AccessNDSMessages.OBJECTS_NOT_DEPLOYED);// Was not sure what to put here? Can change message for LDIF_DATA_UPDATION String //$NON-NLS-1$
         }
         try
         {
            byte[] ldifDatabytes;
            if(null != ldifData && !ldifData.contains( LDIF_VERSION_STRING )){
               ldifDatabytes = byteCombine( (LDIF_VERSION_STRING + EOL).getBytes(), ldifData.getBytes() );
            }else{
               ldifDatabytes=ldifData.getBytes();
            }
            InputStream in = new ByteArrayInputStream( ldifDatabytes );


            LDIFReader reader = new LDIFReader( in );

          LDAPMessage mesg = null;
          LDAPEntry entry;
          boolean flag;

            while ((mesg = reader.readMessage()) != null)
            {
               entry = ((LDAPSearchResult)mesg).getEntry();
               flag = true;
               // It tries to add an object to the eDirectory 
               // If the object is already present in the eDirectory then it will throw an exception
               // It will try to replace the object.
               try 
               {
                        m_connection.add(entry);                        
                        flag = false;
                } 
               catch (LDAPException e)
               {
                   
 
                }finally{
                   if (flag) {
                      // Deleting the object and adding additional object?                      
                       m_connection.delete(entry.getDN());
                       m_connection.add(entry);
                   }
               }
            }
            return true;
         }
         catch (LDAPException e)
         {
            e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }
      else
      {
         result = false;
      }

      return result;
   }
   
   public boolean updateObjects(
      String ldifData, boolean overwrite)
   {
      return updateObjects(ldifData, overwrite, null);
   }
   
   
   /*  Adds/overwrites the objects in eDirectory and logs the status.
    * 
    */
   public boolean updateObjects(
      String ldifData, boolean overwrite, List<String> deployObjects)
   {
      boolean result = true;
      LDAPEntry entry=null;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
         connectIfNotConnected("not deployed");// Was not sure what to put here? Can change message for LDIF_DATA_UPDATION String //$NON-NLS-1$
         try
         {
            byte[] ldifDatabytes;
            if(null != ldifData && !ldifData.contains( LDIF_VERSION_STRING )){
               ldifDatabytes = byteCombine( (LDIF_VERSION_STRING + EOL).getBytes(), ldifData.getBytes() );
            }else{
               ldifDatabytes=ldifData.getBytes();
            }
            InputStream in = new ByteArrayInputStream( ldifDatabytes );


            LDIFReader reader = new LDIFReader( in );

            LDAPMessage mesg = null;
            boolean flag;

            while ((mesg = reader.readMessage()) != null)
            {
               try
               {
                  entry = ((LDAPSearchResult) mesg).getEntry();
                  
         
            
                  
                  flag = true;
                  LDAPAttributeSet as;
                  Iterator allAttrs;
                  LDAPAttribute ldapAttribute=null;
                  // It tries to add an object to the eDirectory 
                  // If the object is already present in the eDirectory then it will throw an exception
                  // It will try to replace the object.
                  try
                  {
                     m_connection.add( entry );
                     flag = false;
                     
                  }
                  catch (LDAPException e)
                  {
                     if (e.getMessage().contains( ENTRY_ALREADY_EXISTS_MESSAGE ))
                     {
                        if (!overwrite)
                        {
//                           statusResults.add( new StatusResult(
//                                 entry.getDN(),
//                                 StatusResult.SEVERITY_WARNING,
//                                 AccessNDSMessages.OBJECT_NOT_ADDED,
//                                 e ) );
                        }
                     }else{
                        // For other kinds of error try updating the eDirectory
                        flag = false;
//                        statusResults.add( new StatusResult(
//                                                            entry.getDN(),
//                                                            StatusResult.SEVERITY_ERROR,
//                                                            AccessNDSMessages.OBJECT_NOT_ADDED,
//                                                            e ) );
                     }
                     
                  }
                  finally
                  {
                     if (overwrite && flag)
                     {
                        // Deleting and adding the object was creating problems when the object had children 
                        // To overcome that problem we are replacing the attributes of the objects 
                        boolean exceptionUpdatingAttribute = false;
                        boolean singleAttributeUpdated = false;
                        // Using String 
                        StringBuilder stringBuilder = new StringBuilder();
                        stringBuilder.append( "" );
                        stringBuilder.append( EOL );
                        stringBuilder.append( EOL );
                        as = entry.getAttributeSet();
                        allAttrs = as.iterator();
                        while (allAttrs.hasNext()) {
                            try {
                               ldapAttribute = (LDAPAttribute) allAttrs.next();
                               m_connection.modify(entry.getDN(),
                                                   new LDAPModification(
                                                                        LDAPModification.REPLACE,
                                                                        ldapAttribute));
                               singleAttributeUpdated = true;
                            }catch(LDAPException e){
                               if(e.toString().contains( NAMING_ATTRIBUTE_ERROR )){
                                  // Don't do anything
                                  // Because naming attribute in an eDirectory object cannot be modified

                               }else{
                                  if (null != ldapAttribute)
                                 {
//                                    // Not a naming attribute problem
//                                    // Some other problem Log error
//                                     stringBuilder.append(AccessNDSMessages.ATTRIBUTE);
//                                     stringBuilder.append( SPACE );
//                                     stringBuilder.append(ldapAttribute.getName());
//                                     stringBuilder.append(SPACE_COLON);
//                                     stringBuilder.append( AccessNDSMessages.PROBLEM );
//                                     stringBuilder.append( SPACE );
//                                     stringBuilder.append(e.getLocalizedMessage());
//                                     stringBuilder.append( EOL );                                   
                                 }
                                  result = false;
                                  exceptionUpdatingAttribute = true;
                               }
                            }

                        }
                        if(exceptionUpdatingAttribute){
                           if(singleAttributeUpdated){
                              //statusResults.add(new StatusResult(entry.getDN(),StatusResult.SEVERITY_WARNING,AccessNDSMessages.OBJECT_ALL_ATTRIBUTES_NOT_UPDATED + stringBuilder.toString(),null));
                              
                           }else{
                        	   //e.printStackTrace();
                           }
                           
                        }else{
                        	//e.printStackTrace();

                        }
                    }
                  }
               }
               catch (Exception e)
               {
            	   e.printStackTrace();
                  result = false;
               }
            }
            return result;
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }
      else
      {
         result = false;
      }
      
      

      return result;
   }
   
   // updates the attribute in the eDirectory
   //pass the attribute to be modified in the attrib (here attrib is something like "memberQueryURL")
   public boolean updateAttribute(
      String context,
      String attrib,
      String modifiedValue )
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            LDAPAttribute attribute = new LDAPAttribute( attrib, modifiedValue ); 
            m_connection.modify( context,
                                 new LDAPModification(
                                       LDAPModification.REPLACE,
                                       attribute ) );
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
             result = false;
         }
         catch (Exception e)
         {
            e.printStackTrace();
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
   // adds an attribute value in the eDirectory
   //pass the attribute to be modified in the attrib (here attrib is something like "memberQueryURL")
   public boolean addAttribute(
      String context,
      String attrib,
      String modifiedValue )
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            LDAPAttribute attribute = new LDAPAttribute( attrib, modifiedValue ); 
            m_connection.modify( context,
                                 new LDAPModification(
                                       LDAPModification.ADD,
                                       attribute ) );
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
   // adds an object to edir
   // pass the object to be added along with the attributes
   public boolean addObject(
      String context,
      Map<String,List<String>> attributes)
   {
      boolean result = true;
   
      
      LDAPAttributeSet attrSet = new LDAPAttributeSet();
      for (String attrCN : attributes.keySet())
      {
         List<String> values = attributes.get( attrCN );
         LDAPAttribute attribute = new LDAPAttribute( attrCN );
         
         for (String value:values)
            attribute.addValue( value );
         
         attrSet.add( attribute );
      }
      
      LDAPEntry entry = new LDAPEntry(context,attrSet);
            
      
      if (!(null == m_connection) && entry != null)
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            m_connection.add( entry );
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
   // adds an attribute value in the eDirectory
   //pass the attribute to be modified in the attrib (here attrib is something like "memberQueryURL")
   public boolean addAttributes(
      String context,
      Map<String,String> attributes)
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      
      List<LDAPModification> attrsMod = new ArrayList<LDAPModification>();
      for (String attrCN : attributes.keySet())
      {
         LDAPAttribute attribute = new LDAPAttribute( attrCN, attributes.get( attrCN ) );
         LDAPModification mod = new LDAPModification(LDAPModification.ADD,
                                       attribute );
         attrsMod.add( mod );
      }
      
      
      if (!(null == m_connection) && attrsMod.size() > 0)
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            //LDAPAttribute attribute = new LDAPAttribute( attrib, modifiedValue ); 
            m_connection.modify( context,
                                 attrsMod.toArray(new LDAPModification[0]) );
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
   
   // replace attribute values in the eDirectory with the new set of values
   //pass the attribute to be modified in the attrib (here attrib is something like "memberQueryURL") 
   // pass the array of new Values.
   public boolean updateAttribute(
      String context,
      String attrib,
      String[] newValues)
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            LDAPAttribute attribute = new LDAPAttribute( attrib, newValues ); 
            m_connection.modify( context,
                                 new LDAPModification(
                                       LDAPModification.REPLACE,
                                       attribute ) );
         }
         catch (LDAPException e)
         {
        	 e.printStackTrace();
            result = false;
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
   // removes an attribute value in the eDirectory
   // pass the attribute name for which values have to be deleted.
   public boolean removeAttribute(
      String context,
      String attrib )
      
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
         if (!m_connection.isConnected())
         {
            connectIfNotConnected("");
         }
         try
         {
            LDAPAttribute attribute = new LDAPAttribute( attrib ); 
            m_connection.modify( context,
                                 new LDAPModification(
                                       LDAPModification.DELETE,
                                       attribute ) );
         }
         catch (LDAPException e)
         {
            String message = ((LDAPException)e).getLDAPErrorMessage();
            
            
            if (!message.contains( Integer.toString( -601 ) ) && !message.contains( Integer.toString( -602 ) ))
            {
            	e.printStackTrace(); 
               result = false;
            }
               
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
             
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }
   
// removes an attribute value in the eDirectory
   // pass the attribute name for which values have to be deleted.
   public boolean removeAttributeValues(
      String context,
      String attrib,
      String[] values)
      
   {
      boolean result = true;
      // If LDAPconnection was closed or timed out it was getting stuck in the while loop
      if (!(null == m_connection))
      {
        
         connectIfNotConnected("");
         try
         {
            
            LDAPAttribute attribute = new LDAPAttribute( attrib, values ); 
            m_connection.modify( context,
                                 new LDAPModification(
                                       LDAPModification.DELETE,
                                       attribute ) );
         }
         catch (LDAPException e)
         {
            String message = ((LDAPException)e).getLDAPErrorMessage();
            
            e.printStackTrace();
          
               
         }
         catch (Exception e)
         {
        	 e.printStackTrace();
             
            result = false;
         }
      }else{
        result = false;
      }
      
      return result;
   }

   // Checks whether the LDAP connection has been established or not?
   // if m_connection is null then it should return null
   public boolean isConnected()
   {
      if (null != m_connection)
      {
         return m_connection.isConnected();
      }
      else
      {
         return false;
      }
   }

   // Basically to avoid initialization when the connection has been timed out
   public void connectIfNotConnected()
   {
      if (!isConnected())
      {
         connectToLDAP();
      }
   }
   
   // Basically to avoid initialization when the connection has been timed out
   public void connectIfNotConnected(String errorMessage)
   {
      if (!isConnected())
      {
         connectToLDAP(errorMessage);
      }
   }
   public static byte[] byteCombine(byte[]   streamData1, byte[]   streamData2 ){
      byte[] result;
      if((null == streamData1)&&(null == streamData2)){
         result = null;
      }else{
         if(null == streamData1){
            int   bl;


            bl       = streamData2.length;
            result = new byte[bl];
            System.arraycopy( streamData2, 0, result, 0, bl );
         }else{
            if(null == streamData2){
               int   bl;


               bl       = streamData1.length;
               result = new byte[bl];
               System.arraycopy( streamData1, 0, result, 0, bl );
            }else{
               int bl1,bl2;
               bl1 = streamData1.length;
               bl2 = streamData2.length;
               result = new byte[bl1 + bl2];
               System.arraycopy( streamData1, 0, result, 0, bl1 );
               System.arraycopy( streamData2, 0, result, bl1, bl2 );
            }
         }
      }
      return result;
   }   
   public void setM_ldapClearPort(
      int clearPort )
   {
      m_ldapClearPort = clearPort;
   }
   public void setM_ldapSecurePort(
      int securePort )
   {
      m_ldapSecurePort = securePort;
   }
   public void setM_useSecurePort(
      boolean securePort )
   {
      m_useSecurePort = securePort;
   }

public boolean modifyUser(User modifyUser, String string) {
	// TODO Auto-generated method stub
	return false;
}
}
