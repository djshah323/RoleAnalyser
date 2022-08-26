package com.ra.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.text.Collator;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.Vector;

import org.json.JSONObject;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;




public class JavaUtil
{
   // A Collator object for perform locale specific String compares.
   private static Collator Collator; 

   /**
    * Returns a cached Collator object for performing String
    * comparisons.
    */
   @SuppressWarnings("static-access")
   public static Collator getCollator()
   {
      // Have we cached a Collator object yet?
      if (null == Collator)
      {
         // No!  Cache one now...
         Collator = Collator.getInstance();
         Collator.setStrength( Collator.IDENTICAL );
      } // if
   
      // ...and return it.
      return (Collator);
   } // getCollator

   /**
    * Copies length bytes of bytes into a newly allocated byte[].
    */
   public static byte[] copyByteArray(
      byte[] bytes, // The source byte[] to copy.
      int length ) // The number of bytes of bytes to copy.
   {
      byte[] reply;
   
   
      // Validate the copy length...
      if (0 > length)
      {
         length = 0;
      } // if
   
      // ...copy the bytes...
      reply = new byte[length];
      System.arraycopy( bytes,
                        0,
                        reply,
                        0,
                        length );
   
      // ...and return the copy.
      return reply;
   } // copyByteArray

   /**
    * Get the size of a double byte array
    *
    * @param byteArray Double Byte array
    * @return Size of the arrays.
    */
   public static int byteArraySize(
      byte[][] byteArray )
   {
      int size = 0;
   
      for (int i = 0; i < byteArray.length; i++)
      {
         size += byteArray[i].length;
      }
   
      return size;
   }

   /**
    * Returns the Vector equivalent of an ArrayList.
    *
    * This is required to satisfy the coding standards AND work with
    * the NDSNamespace.  There are API's in the NDSNamespace that
    * require Vector's.  We work with ArrayLists EVERYWHERE and convert
    * them to Vector's only when needed.
    */
   public static Vector<Object> alToV(
      List<?> al ) // The ArrayList to convert to a Vector.
   {
      int count;
      int i;
      Vector<Object> reply;
   
   
      // Were we give an ArrayList?
      if (null == al)
      {
         // No!  Then don't return a Vector.
         return null;
      } // if
   
   
      // Scan the ArrayList...
      reply = new Vector<Object>();
      count = al.size();
      for (i = 0; i < count; i += 1)
      {
         // ...copying each entry to the Vector.
         reply.addElement( al.get( i ) );
      } // for
   
   
      // If we get here, reply refers to the Vector equivalent of the
      // ArrayList.  Return it.
      return reply;
   } // alToV

   /**
    * Returns true if two byte[]'s contain the same data and false
    * otherwise.
    */
   public static boolean byteArraysAreEqual(
      byte[] ba1, // The first  byte[] to compare.
      byte[] ba2 ) // The second byte[] to compare.
   {
      int i;
      int l1;
      int l2;
   
   
      // Do the two byte[]'s contain the same number of bytes?
      l1 = ((null == ba1) ? 0 : ba1.length);
      l2 = ((null == ba2) ? 0 : ba2.length);
      if (l1 != l2)
      {
         // No!  Then they can't be the same.
         return false;
      } // if
   
   
      // Scan the byte[]'s bytes...
      for (i = 0; i < l1; i += 1)
      {
         // Are these bytes the same?
         if (ba1[i] != ba2[i])
         {
            // No!  Then the byte[]'s can't be the same.
            return false;
         } // if
      } // for
   
   
      // If we get here, the byte[]'s are equal.  Return true.
      return true;
   } // byteArraysAreEqual

   /**
    * Converts a boolean value into Boolean.
    * 
    * @param bool The boolean to convert
    * 
    * @return The corresponding Boolean object (TRUE or FALSE).
    */
   public static Boolean toBoolean(
      boolean bool )
   {
      if (bool)
      {
         return Boolean.TRUE;
      }
      else
      {
         return Boolean.FALSE;
      }
   }

   /**
    * Does a byte[] contain any data?
    */
   public static boolean hasBytes(
      byte[] data ) // Does this byte[] contain any data?
   {
      return (null != data) && (0 < data.length);
   } // hasBytes

   /**
    * Does a String contain any data?
    */
   public static boolean hasString(
      String s ) // The String to check for data.
   {
      return (null != s) && (0 < s.trim().length());
   } // hasString

   public static boolean hasStringWithSpaces(
      String s )
   {
      return (null != s) && (0 < s.length());
   }

   /**
    * Is the String a valid integer?
    */
   public static boolean isInteger(
      String s )
   {
      boolean isInt = true;
   
      try
      {
         Integer.parseInt( s );
      }
      catch (NumberFormatException ex)
      {
         isInt = false;
      }
   
      return isInt;
   }// end isInteger()

   /**
    * Is the String a valid long?
    */
   public static boolean isLong(
      String s )
   {
      boolean isLong = true;
   
      try
      {
         Long.parseLong( s );
      }
      catch (NumberFormatException ex)
      {
         isLong = false;
      }
   
      return isLong;
   }// end isInteger()
   /**
    * Is the String a valid real?
    */
   public static boolean isReal(
      String s )
   {
      boolean isReal = true;
   
      try
      {
         Double.parseDouble( s );
      }
      catch (NumberFormatException ex)
      {
         isReal = false;
      }
   
      return isReal;
   }// end isInteger()

   /**
    * Parse off the tree name from a DN.  This will find the
    * 2nd slash after the tree name
    *
    * @return String - Tree name
    */
   public static String parseTreeName(
      String dn )
   {
      int pos = dn.indexOf( "\\", //$NON-NLS-1$
                            1 );
   
      if (pos == -1)
      {
         return dn.substring( 1 );
      }
   
      return dn.substring( 0,
                           pos ).substring( 1 );
   }

   /**
    * Parse off the name from a DN.  This will return the last
    * element.
    *
    * @return String - Name portion of the dn
    */
   public static String parseSlashName(
      String dn )
   {
      return dn.substring( dn.lastIndexOf( "\\" ) + 1 ); //$NON-NLS-1$
   }

   /**
    * Reverses the items in the String[] aIn.
    */
   public static String[] reverseSArray(
      String[] aIn ) // The String[] whose items are to be reversed.
   {
      int c;
      int i;
      int j;
      String[] reply;
   
   
      // We're we given a String[] to reverse?
      if (null == aIn)
      {
         // No!  Bail.
         return null;
      } // if
   
   
      // Allocate a String[] to return;
      c = aIn.length;
      reply = new String[c];
   
   
      // Scan the source String[]...
      for (i = 0, j = (c - 1); i < c; i += 1, j -= 1)
      {
         // ...copying items to the target String[].
         reply[i] = aIn[j];
      } // for
   
   
      // If we get here, reply refers to the reversed version of
      // aIn.  Return it.
      return reply;
   } // reverseSArray

   /**
    * Returns the index of a String from an array of String's.
    */
   public static int sInA(
      String s, // The String to search the array for.
      String[] a ) // The array to search for the String.
   {
      // Were we given a String to search for?
      if (hasString( s ))
      {
         int c;
         int i;
   
   
         // Yes!  Scan the array.
         c = ((null == a) ? 0 : a.length);
         for (i = 0; i < c; i += 1)
         {
            // Is this the String in question?
            if (s.equalsIgnoreCase( a[i] ))
            {
               // Yes!  Return its index.
               return i;
            } // if
         } // for
      } // if
   
   
      // If we get here, the String couldn't be found in the array.
      // Return -1.
      return -1;
   } // sInA

   /**
    * Returns the index of a String from an ArrayList of String's.
    */
   public static int sInAL(
      String s, // The String to search the ArrayList for.
      ArrayList<String> al ) // The ArrayList to search for the String.
   {
      // Were we given a String to search for?
      if (hasString( s ))
      {
         int c;
         int i;
   
   
         // Yes!  Scan the ArrayList.
         c = ((null == al) ? 0 : al.size());
         for (i = 0; i < c; i += 1)
         {
            // Is this the String in question?
            if (s.equalsIgnoreCase( al.get( i ) ))
            {
               // Yes!  Return its index.
               return i;
            } // if
         } // for
      } // if
   
   
      // If we get here, the String couldn't be found in the ArrayList.
      // Return -1.
      return -1;
   } // sInAL

   /**
    * Returns the index of a String from a Vector of String's.
    */
   public static int sInV(
      String s, // The String to search the Vector for.
      Vector<String> v ) // The Vector to search for the String.
   {
      // Were we given a String to search for?
      if (hasString( s ))
      {
         int c;
         int i;
   
   
         // Yes!  Scan the Vector.
         c = ((null == v) ? 0 : v.size());
         for (i = 0; i < c; i += 1)
         {
            // Is this the String in question?
            if (s.equalsIgnoreCase( v.elementAt( i ) ))
            {
               // Yes!  Return its index.
               return i;
            } // if
         } // for
      } // if
   
   
      // If we get here, the String couldn't be found in the Vector.
      // Return -1.
      return -1;
   } // sInV

   /**
    * Implements a case ignore String.indexOf function.
    */
   public static int ciIndexOf(
      String s1, // Search this String for...
      String s2 ) // ...the first occurence of this String.
   {
      if (null == s1)
      {
         s1 = ""; //$NON-NLS-1$
      }
   
      if (null == s2)
      {
         s2 = ""; //$NON-NLS-1$
      }
   
      return s1.toUpperCase().indexOf( s2.toUpperCase() );
   } // ciIndexOf

   /**
    * Converts a String containing 'true' or 'false' to the appropriate
    * boolean value.  If the String contains 'true', true is returned.
    * If it contains anything else, false is returned.
    */
   public static boolean sToB(
      String bString ) // Boolean String to convert to a boolean value.
   {
      return JavaUtil.hasString( bString ) && bString.equalsIgnoreCase( "true" ); //$NON-NLS-1$
   } // sToB

   /**
    * Removes all the items stored in an ArrayList.
    */
   public static void emptyAL(
      List<? extends Object> al ) // The ArrayList to be emptied.
   {
      // If we were given an ArrayList to empty...
      if (null != al)
      {
         // ...empty it.
         al.clear();
      } // if
   } // emptyAL

   /**
    * Determines if the given value is a numeric string
    * Valid NU string characters include 0..9 digits and the space
    */
   public static boolean isNUString(
      String nuString ) // Boolean String to convert to a boolean value.
   {
	   if (nuString != null) {
		   for (int i=0;i<nuString.length();i++) {
			   char ch = nuString.charAt(i);
			   if (ch == ' ') {
				   continue; 
			   }
			   try {
				   Integer.parseInt("" + ch); 
			   }
			   catch (NumberFormatException e) {
				   return false; 
			   }
		   }
	   }
	   return true; 
   } // isNUString

   /**
    * Determines if the given value is a printable string
    * Valid PR string characters include
    * 	A..Z, a..z, 0..9, 0x20, or '()+,-./:=?  
    *   
    */
   public static boolean isPRString(
      String prString ) // Boolean String to convert to a boolean value.
   {
	   if (prString != null) {
		   for (int i=0;i<prString.length();i++) {
			   char ch = prString.charAt(i);
			   if (((ch >= 0x30) && (ch<=0x39)) //0..9
				   		|| ((ch >= 0x41) && (ch<=0x5A)) //A..Z
				   		|| ((ch >= 0x61) && (ch<=0x7A)) //a..z
				   		|| (ch >= 0x20) //space
				   		|| (ch == 0x27) //single quote
				   		|| (ch == 0x28) //left parenthesis 
				   		|| (ch == 0x29) //right parenthesis
				   		|| (ch >= 0x2B)	//plus
				   		|| (ch >= 0x2C) //comma
				   		|| (ch >= 0x2D) //hyphen - minus sign
				   		|| (ch >= 0x2E) //period
				   		|| (ch >= 0x2F) //slash
				   		|| (ch >= 0x3A) //colon
				   		|| (ch >= 0x3D) //equal
				   		|| (ch >= 0x3F)) //question
			   {
				   continue; 
			   }
			   else
			   {
				   return false; 
			   }
		   }
	   }
	   else {
		   return false; 
	   }
	   return true; 
   } // isNUString
   
   public static String readStream(InputStream is)
   {
       final char[] buffer = new char[0x10000];
       StringBuilder out = new StringBuilder();
       Reader in;
       BufferedReader bufferedReader = null;
       try {
           bufferedReader = new BufferedReader(new InputStreamReader(is,
                   "UTF-8")); //$NON-NLS-1$

           int read;
           do {
               read = bufferedReader.read(buffer, 0, buffer.length);
               if (read > 0) {
                   out.append(buffer, 0, read);
               }
           } while (read >= 0);
       } catch (UnsupportedEncodingException e) {
           // TODO Auto-generated catch block
           e.printStackTrace();
       } catch (IOException e) {
           // TODO Auto-generated catch block
           e.printStackTrace();
       }
       return out.toString();
   }
   

   
	private static String getLdapFilter(String str, String type) {
		char[] in = str.toCharArray();
		Stack<Character> stack = new Stack<Character>();
		StringBuilder out = new StringBuilder();

		for (int i = 0; i < in.length; i++)
		{
			switch (in[i]) {
			case '+':
			case '#':
				out.append(' ');
				stack.push(in[i]);
				out.append(' ');
				break;
			case '(':
				break;
			case ')':
				if (!stack.empty()) {
					out.append(' ');
					out.append(stack.pop());
				}
				break;
			default:
				out.append(in[i]);
				break;
			}
		}

		while (!stack.isEmpty()) {
			out.append(' ');
			out.append(stack.pop());
		}

		return evaluateOutputFilter(out.toString(), type);
	}
	 
	private static String convertSCIMAttrToLDAP(String inputStr, String type)
	{
		StringBuilder strBuilder = new StringBuilder();
		if (inputStr != null) {
			if (inputStr.contains("<")) {
				int equalIndex = inputStr.indexOf("<");
				String key = getMappingForAttribute(inputStr.substring(0, equalIndex), type);
				strBuilder.append(key);
				strBuilder.append('=');
				strBuilder.append(inputStr.substring(equalIndex+1));
				strBuilder.append('*');
			} else if (inputStr.contains(">")) {
				int equalIndex = inputStr.indexOf(">");
				String key = getMappingForAttribute(inputStr.substring(0, equalIndex), type);
				strBuilder.append(key);
				strBuilder.append("=*");
				strBuilder.append(inputStr.substring(equalIndex+1));
				strBuilder.append('*');
			} else if (inputStr.contains("=")) {
				int equalIndex = inputStr.indexOf("=");
				String key = getMappingForAttribute(inputStr.substring(0, equalIndex), type);
				strBuilder.append(key);
				strBuilder.append("=");
				strBuilder.append(inputStr.substring(equalIndex+1));
			}
		}
		return strBuilder.length() == 0 ? inputStr : strBuilder.toString();
	}
	
	private static String evaluateOutputFilter(String str, String type)
	{
		String[] splits = str.split(" +");
		StringBuilder outString = new StringBuilder();
		Stack<String> stack = new Stack<String>();
		
		for (int i = 0; i < splits.length; i++)
		{
			if ("+".equals(splits[i])) {
				String str1 = null;
				String str2 = null;
				if (!stack.isEmpty()) {
					str1 = convertSCIMAttrToLDAP(stack.pop(), type);
					if (outString.length() == 0 && !stack.isEmpty()) {
						str2 = convertSCIMAttrToLDAP(stack.pop(), type);
						outString.append("(&(" + str1 + ")" + "(" + str2 + "))");
					} else {
						outString.insert(0, "(&(" + str1 + ")");
						outString.insert(outString.length()-1, ")");
					}
				}
			} else if ("#".equals(splits[i])) {
				String str1 = null;
				String str2 = null;
				if (!stack.isEmpty()) {
					str1 = convertSCIMAttrToLDAP(stack.pop(), type);
					if (outString.length() == 0 && !stack.isEmpty()) {
						str2 = convertSCIMAttrToLDAP(stack.pop(), type);
						outString.append("(|(" + str1 + ")" + "(" + str2 + "))");
					}  else {
						outString.insert(0, "(|(" + str1 + ")");
						outString.insert(outString.length()-1, ")");
					}
				}
			} else {
				stack.push(splits[i]);
			}
		}
		return outString.length() == 0 ? convertSCIMAttrToLDAP(str, type) : outString.toString();
	}
	
	public static String getPrettyPrintString(JSONObject result) {
		String indented = "";
		if (result != null) {
			try {
				ObjectMapper mapper = new ObjectMapper();
				Object json = mapper.readValue(result.toString(), Object.class);

				indented = mapper.writer().withDefaultPrettyPrinter()
						.writeValueAsString(json);
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return result.toString();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return result.toString();
			}
		}
		return indented;
	}
	
	public static String getStringArrayToString(String[] values)
	{
		StringBuilder value = new StringBuilder();
		if (values != null) {
			
			boolean isFirst = true;
			for (String s : values) {
				if (!isFirst) {
					value.append("#");
				}
				value.append(s);
				isFirst = false;
			}
		}
		return value.toString();
	}
	
}
