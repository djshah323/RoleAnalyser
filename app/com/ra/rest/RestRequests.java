package com.ra.rest;

import javax.ws.rs.core.MediaType;

import com.novell.ldap.util.Base64;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import sun.awt.image.URLImageSource;


public class RestRequests {
	
	private String _uaURL; 
	private static final Client restClient =  Client.create();;
	/**
	 * Constructor
	 * 
	 * @param uaURL
	 * @param authStr
	 */
	public RestRequests(String uaURL) {
		_uaURL = uaURL;
	}

	public String createResource(String authInfo, 
								 String nativeName, 
								 String driverName, 
								 String entDn, 
								 String codeMapKey, 
								 String multiValued,
								 String llid) throws Exception{
		
		String createdResourceDN = null;
		JSONObject newRequest = new JSONObject();
		StringBuilder resourceBuilder = new StringBuilder(nativeName);
		resourceBuilder.append("_");
		resourceBuilder.append(llid);
		resourceBuilder.append("_");
		resourceBuilder.append(driverName);
		String resourceName = resourceBuilder.toString();
		//debug(String.format("Create Resource: %s Entitlement: %s", resourceName, entDn)); 
		try
		{
			newRequest.put("id","");
			newRequest.put("categories", new JSONArray());
			newRequest.put("owners", new JSONArray());
			
			JSONArray entitlements = new JSONArray();
				JSONObject newEntitlement =  new JSONObject();
				newEntitlement.put("id", entDn);
				newEntitlement.put("parameterName", nativeName);
				newEntitlement.put("parameterValue", "%EntitlementParamKey%");
				newEntitlement.put("resourceName", resourceName);
				newEntitlement.put("action","0");
				newEntitlement.put("correlationId","");
				newEntitlement.put("name", nativeName);
				newEntitlement.put("displayName",resourceName);
				newEntitlement.put("description","Dynamic Resource for " + nativeName + "_" + llid);
				newEntitlement.put("type","APP_QUERY_PARAMS");
			entitlements.put(newEntitlement);
			
			newRequest.put("entitlements", entitlements);
			
			JSONArray resourceParameters = new JSONArray();
				JSONObject resourceParameter =  new JSONObject();
				resourceParameter.put("id", "EntitlementParamKey");
				resourceParameter.put("binding", "dynamic");
				resourceParameter.put("codeMapKey", codeMapKey + ":" + llid);
				resourceParameter.put("type", "EntitlementRef");
				resourceParameter.put("displayValue", nativeName);
				resourceParameter.put("entitlementDn",entDn);
				resourceParameter.put("staticValue", "");
				resourceParameter.put("scope","user");
				resourceParameter.put("instance",true);
				resourceParameter.put("hide",false);
				resourceParameter.put("multiValue",multiValued.equalsIgnoreCase("true") ? true : false);
			resourceParameters.put(resourceParameter);
			
			newRequest.put("resourceParameters", resourceParameters);
			
			newRequest.put("allowMultiple",multiValued.equalsIgnoreCase("true") ? true : false);
			newRequest.put("approvalOverRide",false);
			newRequest.put("approvalRequired",false);
			newRequest.put("revokeRequired",false);
			newRequest.put("fromEntitlement",true);
			newRequest.put("isExisted",true);
			
			WebResource resource = restClient.resource(_uaURL);
			String payloadRequest = newRequest.toString();
			String uaAuth = "Basic " + Base64.encode(authInfo);
			String response = resource
					.type("application/json")
			        .header("Authorization", uaAuth)
			        .post(String.class, payloadRequest);
			
			//debug(String.format("Create Resource returned: %s", response)); 
			
			JSONObject respJson = new JSONObject(response);
			if(respJson.has("success"))
			{
				if(respJson.getBoolean("success")){
					createdResourceDN = respJson.getJSONArray("succeeded").getJSONObject(0).getString("id");
				}
				else{
					//check if resource already exists
					JSONObject failStatus = respJson.getJSONArray("failed").getJSONObject(0);
					if(failStatus.getString("reason").contains("Resource already exists")){
						createdResourceDN = failStatus.getString("id");
					}
					else{
						String msg = String.format("Error creating resource: %s Error: %s", resourceName,failStatus.getString("reason"));
						throw new Exception(msg);
					}
				}
			}
			return createdResourceDN;
		}catch (JSONException e) {
		    throw new Exception("Error constructing resource payload"); 
		}
		catch(UniformInterfaceException e){
			int respCode = e.getResponse().getStatus();
			
			if (respCode == 404) {
			    throw new Exception(String.format("Invalid service URL: %s", _uaURL)); 
			} else if (respCode == 403) {
			    throw new Exception(String.format("Invalid Authentication or Forbidden operation: %s", _uaURL));

			} else {
			    throw new Exception(String.format("Error (%d) creating resource: %s Message: %s", 
						respCode, resourceName, e.getMessage())); 
			}
		}
	}
}
