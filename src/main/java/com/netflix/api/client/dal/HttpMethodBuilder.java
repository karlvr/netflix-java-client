package com.netflix.api.client.dal;

import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import net.oauth.OAuth;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netflix.api.NetflixAPIException;
import com.netflix.api.NetflixAPIResponse;
import com.netflix.api.client.APIEndpoints;
import com.netflix.api.client.NetflixAPIClient;
import com.netflix.api.client.NetflixAPICustomer;
import com.netflix.api.client.oauth.OAuthAccessToken;
import com.netflix.api.client.oauth.OAuthRequestToken;
import com.netflix.api.client.oauth.OAuthUtils;

/**
 * Builds methods for making HTTP calls to the Netflix API.
 * 
 * @author jharen
 */
public class HttpMethodBuilder
{
	private static final Logger logger = LoggerFactory.getLogger(HttpMethodBuilder.class);
	
	/**
	 * Backreference to parent APIClient.
	 */
	private NetflixAPIClient netflixAPIClient;
	
	/**
	 * Makes http calls and returns results.
	 */
	private HttpClient httpClient = null;
	
	public HttpMethodBuilder(NetflixAPIClient netflixAPIClient)
	{
		this.netflixAPIClient = netflixAPIClient;
		this.httpClient = this.netflixAPIClient.getHttpClient();
	}
	
	/**
	 * @param props  
	 */
	public HttpMethodBuilder(NetflixAPIClient netflixAPIClient, Properties props)
	{
		this.netflixAPIClient = netflixAPIClient;
		this.httpClient = this.netflixAPIClient.getHttpClient();
	}
	
    /**
     * Creates a Map of OAuth key/value pairs preset
     * with default values.
     * @return
     */
    public Map<String, String> getDefaultOAuthParameters()
    {
    	HashMap<String, String> parameters = new HashMap<String, String>();
    	parameters.put("oauth_consumer_key", this.netflixAPIClient.getConsumerKey());
    	parameters.put("oauth_timestamp", OAuthUtils.getNewOAuthTimeStamp());
    	parameters.put("oauth_nonce", OAuthUtils.getNewNonceValue());
    	parameters.put("oauth_signature_method", this.netflixAPIClient.getSignatureMethod());
    	parameters.put("oauth_version", this.netflixAPIClient.getOauthVersion());
    	return parameters;
    }
	
	/**
     * Builds a Http GET Method ready for execution.  <br />
     * The GET method returned has been preset with the 
     * "consumer key only" level authorization (see 
     * http://developer.netflix.com/docs/Security#0_18325 for more info).
     * The GETs hereby returned are applicable for the the autocomplete 
     * resource of the REST API and the Javascript API.
     * 
     * @param uri - the resource URI to call.
     * @param parameters - map of request parameters to send in request.
     * @return - GET method with valid auth header set. 
     */
	public HttpGet buildConsumerKeyedHttpGet(String uri, Map<String, String> parameters) throws Exception
	{
    	HttpGet method = this.newHttpGet(createURIWithQueryString(uri, parameters));
    	HttpClientParams.setAuthenticating(method.getParams(), false);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ GET " + method.getURI() + " ]";
    		logger.debug(message);
    	}
    	return method;
    }

	/**
     * Builds a Http GET Method ready for execution.  <br />
     * The GET method returned has been preset with the 
     * "consumer key + signature" level authorization (see 
     * http://developer.netflix.com/docs/Security#0_18325 for more info).
     * The GETs hereby returned are applicable for calls NOT requiring
     * user auth, and all the back-channel talk between the service provider
     * and consumer applications.
     * 
     * @param uri - the resource URI to call.
     * @param parameters - map of request parameters to send in request.
     * @return - GET method with valid auth header set. 
     * @throws Exception - if signature generation fails
     */
    public HttpGet buildConsumerSignedHttpGet(String uri, Map<String, String> parameters) throws Exception
    {
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("GET", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), null);
    	
    	parameters.put("oauth_signature",signatureParameter);
    	String authHeader = this.createAuthorizationHeader(parameters);
    	
    	HttpGet method = this.newHttpGet(createURIWithQueryString(uri, withoutOauthParams(parameters)));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	method.setHeader("Authorization", authHeader);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ GET " + uri 
    		+ "\n Authorization: " +
    				authHeader + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
	/**
     * Builds a Http GET Method ready for execution.  <br />
     * The GET method returned has been preset with the 
     * "consumer key + signature" level authorization (see 
     * http://developer.netflix.com/docs/Security#0_18325 for more info).
     * The GETs hereby returned are applicable for calls NOT requiring
     * user auth, and all the back-channel talk between the service provider
     * and consumer applications.
     * 
     * @param uri - the resource URI to call.
     * @param parameters - map of request parameters to send in request.
     * @return - GET method with aut params encoding as url parameters. 
     * @throws Exception - if signature generation fails
     */
    public HttpGet buildConsumerSignedHttpGetWithQueryString(String uri, Map<String, String> parameters) throws Exception
    {
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("GET", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), null);
    	
    	parameters.put("oauth_signature", signatureParameter);
    	HttpGet method = this.newHttpGet(createURIWithQueryString(uri, parameters));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ GET " + method.getURI() + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
	/**
     * Builds a Http POST Method ready for execution.  <br />
     * The POST method returned has been preset with the 
     * "consumer key + signature" level authorization (see 
     * http://developer.netflix.com/docs/Security#0_18325 for more info).
     * The POSTS hereby returned are applicable for calls NOT requiring
     * user auth, and all the back-channel talk between the service provider
     * and consumer applications.
     * 
     * @param uri - the resource URI to call.
     * @param parameters - map of request parameters to send in request.
     * @return - POST method with valid auth header set. 
     * @throws Exception - if signature generation fails
     */
    public HttpPost buildConsumerSignedHttpPost(String uri, Map<String, String> parameters) throws Exception
    {
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("POST", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), null);
    	
    	parameters.put("oauth_signature",signatureParameter);
    	String authHeader = this.createAuthorizationHeader(parameters);
    	
    	HttpPost method = this.newHttpPost(createURIWithQueryString(uri, withoutOauthParams(parameters)));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	method.setHeader("Authorization", authHeader);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ POST " + uri 
    		+ "\n Authorization: " +
    				authHeader + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
    /**
     * Builds a Http GET Method ready for execution.  <br />
     * The GET returned has a valid, resource-specific access token
     * pre-loaded and ready to go.
     * 
     * @param uri
     * @param parameters
     * @param customer
     * @return
     * @throws Exception
     */
    public HttpGet buildCustomerAuthorizedHttpGet(String uri, Map<String, String> parameters, NetflixAPICustomer customer) throws Exception
    {
    	OAuthAccessToken accessToken = customer.getAccessToken();
    	if (accessToken == null)
    		throw new NetflixAPIException("Customer has no access token.");
    	return this.buildConsumerSignedHttpGetWithAccessSecret(uri, parameters, accessToken);
    }

    /**
     * Builds a Http POST Method ready for execution.  <br />
     * The POST returned has a valid, resource-specific access token
     * pre-loaded and ready to go.
     * 
     * @param uri
     * @param parameters
     * @param customer
     * @return
     * @throws Exception
     */
    public HttpPost buildCustomerAuthorizedHttpPost(String uri, Map<String, String> parameters, NetflixAPICustomer customer) throws Exception
    {
    	OAuthAccessToken accessToken = customer.getAccessToken();
    	if (accessToken == null)
    		throw new NetflixAPIException("Customer has no access token.");
    	return this.buildConsumerSignedHttpPostWithAccessSecret(uri, parameters, accessToken);
    }
    
    /**
     * Builds a Http DELETE Method ready for execution.  <br />
     * The DELETE returned has a valid, resource-specific access token
     * pre-loaded and ready to go.
     * 
     * @param uri
     * @param parameters
     * @param customer
     * @return
     * @throws Exception
     */
    public HttpDelete buildCustomerAuthorizedHttpDelete(String uri, Map<String, String> parameters, NetflixAPICustomer customer) throws Exception
    {
    	OAuthAccessToken accessToken = customer.getAccessToken();
    	if (accessToken == null)
    		throw new NetflixAPIException("Customer has no access token.");
    	return this.buildConsumerSignedHttpDeleteWithAccessSecret(uri, parameters, accessToken);
    }
    
    /**
     * Builds a Http DELETE Method ready for execution.  <br />
     * The DELETE returned has a valid, resource-specific access token
     * pre-loaded and ready to go.
     * 
     * @param uri
     * @param parameters
     * @param customer
     * @return
     * @throws Exception
     */
    public HttpDelete buildCustomerAuthorizedHttpDelete(String uri, Map<String, String> parameters, NetflixAPICustomer customer, 
    		Map<String, String> requestHeaders) throws Exception
    {
    	OAuthAccessToken accessToken = customer.getAccessToken();
    	if (accessToken == null)
    		throw new NetflixAPIException("Customer has no access token.");
    	return (HttpDelete) this.applyRequestHeadersToMethod(this.buildConsumerSignedHttpDeleteWithAccessSecret(uri, parameters, accessToken), requestHeaders);
    }
    
    /**
     * Builds a Http GET Method ready for execution.  <br />
     * The GET returned has a valid, resource-specific access token
     * pre-loaded and ready to go.
     * 
     * @param uri
     * @param parameters
     * @param customer
     * @return
     * @throws Exception
     */
    public HttpGet buildCustomerAuthorizedHttpGet(String uri, Map<String, String> parameters, NetflixAPICustomer customer,
    		Map<String, String> requestHeaders) throws Exception
    {
    	OAuthAccessToken accessToken = customer.getAccessToken();
    	if (accessToken == null)
    		throw new NetflixAPIException("Customer has no access token.");
    	return (HttpGet) this.applyRequestHeadersToMethod(this.buildConsumerSignedHttpGetWithAccessSecret(uri, parameters, accessToken), requestHeaders);
    }

    /**
     * Builds a Http POST Method ready for execution.  <br />
     * The POST returned has a valid, resource-specific access token
     * pre-loaded and ready to go.
     * 
     * @param uri
     * @param parameters
     * @param customer
     * @return
     * @throws Exception
     */
    public HttpPost buildCustomerAuthorizedHttpPost(String uri, Map<String, String> parameters, NetflixAPICustomer customer,
    		Map<String, String> requestHeaders) throws Exception
    {
    	OAuthAccessToken accessToken = customer.getAccessToken();
    	if (accessToken == null)
    		throw new NetflixAPIException("Customer has no access token.");
    	return (HttpPost) this.applyRequestHeadersToMethod(this.buildConsumerSignedHttpPostWithAccessSecret(uri, parameters, accessToken), requestHeaders);
    }
    
	/**
	 * Retrieves an access token for the specified user, using their Netflix credentials.<br />
	 * Note: this method requires the user give you their username and password.  It is against
	 * the Netflix TOS and as such is deprecated.  In other words, using this can get you busted.
	 * DON'T USE THIS!
	 * @param customer
	 * @return
	 * @throws Exception
	 */
    @Deprecated
	public OAuthAccessToken getAccessTokenFromServiceWithUserCredentials(NetflixAPICustomer customer) throws Exception
	{
		OAuthAccessToken accessToken;
		OAuthRequestToken requestToken = this.getNewRequestToken();
		this.authorizeRequestToken(requestToken, customer);
		accessToken = this.exchangeRequestForAccessToken(requestToken);
		customer.setAccessToken(accessToken);
		return accessToken;
	}
    
    /**
     * Builds the method used to obtain access tokens.
     * @param uri
     * @param parameters
     * @return HttpGet - method that when called will return an access token.
     * @throws Exception
     */
    private HttpGet buildAccessTokenRequestMethod(String uri, Map<String, String> parameters, OAuthRequestToken authorizedRequestToken) throws Exception
    {
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("GET", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), authorizedRequestToken.getTokenSecret());
    	
    	parameters.put("oauth_signature", signatureParameter);
    	
    	HttpGet method = this.newHttpGet(createURIWithQueryString(uri, parameters));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ GET " + method.getURI() + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
    /**
     * Builds a HttpGet suitable for full-security OAuth requests.
     * @param uri
     * @param parameters
     * @return HttpGet 
     * @throws Exception
     */
    protected HttpGet buildConsumerSignedHttpGetWithAccessSecret(String uri, Map<String, String> parameters, OAuthAccessToken accessToken) throws Exception
    {
    	parameters.put("oauth_timestamp", OAuthUtils.getNewOAuthTimeStamp());
    	parameters.put("oauth_nonce", OAuthUtils.getNewNonceValue());
    	parameters.put("oauth_token", accessToken.getTokenText());
    	
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("GET", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), accessToken.getTokenSecret());
    	
    	parameters.put("oauth_signature", signatureParameter);
    	
    	HttpGet method = this.newHttpGet(createURIWithQueryString(uri, parameters));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ GET " + method.getURI() + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
    /**
     * Builds a HttpPost suitable for full-security OAuth requests.
     * @param uri
     * @param parameters
     * @return
     * @throws Exception
     */
    protected HttpPost buildConsumerSignedHttpPostWithAccessSecret(String uri, Map<String, String> parameters, OAuthAccessToken accessToken) throws Exception
    {
    	parameters.put("oauth_timestamp", OAuthUtils.getNewOAuthTimeStamp());
    	parameters.put("oauth_nonce", OAuthUtils.getNewNonceValue());
    	parameters.put("oauth_token", accessToken.getTokenText());
    	
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("POST", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), accessToken.getTokenSecret());
    	
    	parameters.put("oauth_signature", signatureParameter);
    	String authHeader = this.createAuthorizationHeader(parameters);
    	
    	HttpPost method = new HttpPost(createURIWithQueryString(uri, withoutOauthParams(parameters)));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	method.setHeader("Authorization", authHeader);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ POST " + uri 
    		+ "\n Authorization: " +
    				authHeader + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
    /**
     * @param uri
     * @param parameters
     * @return
     * @throws Exception
     */
    public HttpPost buildConsumerSignedHttpPostWithAccessSecretAndQueryString(String uri, Map<String, String> parameters, OAuthAccessToken accessToken) throws Exception
    {
    	parameters.put("oauth_timestamp", OAuthUtils.getNewOAuthTimeStamp());
    	parameters.put("oauth_nonce", OAuthUtils.getNewNonceValue());
    	parameters.put("oauth_token", accessToken.getTokenText());
    	
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("POST", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), accessToken.getTokenSecret());
    	
    	parameters.put("oauth_signature", signatureParameter);
    	
    	HttpPost method = new HttpPost(createURIWithQueryString(uri, parameters));
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ POST " + method.getURI() + "]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
    /**
     * Builds a HttpDelete suitable for full-security OAuth requests.
     * @param uri
     * @param parameters
     * @return
     * @throws Exception
     */
    protected HttpDelete buildConsumerSignedHttpDeleteWithAccessSecret(String uri, Map<String, String> parameters, OAuthAccessToken accessToken) throws Exception
    {
    	HttpDelete method = this.newHttpDelete(uri);
    	HttpClientParams.setAuthenticating(method.getParams(), true);
    	
    	parameters.put("oauth_timestamp", OAuthUtils.getNewOAuthTimeStamp());
    	parameters.put("oauth_nonce", OAuthUtils.getNewNonceValue());
    	parameters.put("oauth_token", accessToken.getTokenText());
    	
    	String signatureBaseString = OAuthUtils.getSignatureBaseString("DELETE", uri, parameters);
    	String signatureParameter = OAuthUtils.getHMACSHASignature(signatureBaseString, this.netflixAPIClient.getConsumerSecret(), accessToken.getTokenSecret());
    	
    	parameters.put("oauth_signature", signatureParameter);
    	String authHeader = this.createAuthorizationHeader(parameters);
    	
    	method.setHeader("Authorization", authHeader);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ DELETE " + uri 
    		+ "\n Authorization: " +
    				authHeader + " ]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
	/**
     * Performs the first major step in the sublime dance that is OAuth:
     * this retrieves a plain-vanilla, unauthorized request token from
     * the service provider.
     * 
     * @return
     * @throws Exception
     */
    public OAuthRequestToken getNewRequestToken() throws Exception
    {
    	return this.getNewRequestToken(null);
    }
    
    /**
     * Performs the first major step in the sublime dance that is OAuth:
     * this retrieves a plain-vanilla, unauthorized request token from
     * the service provider.
     * 
     * @return
     * @throws Exception
     */
    public OAuthRequestToken getNewRequestToken(Map<String, String> requestHeaders) throws Exception
    {
    	OAuthRequestToken token = null;
    	Map<String, String> parameters = this.getDefaultOAuthParameters();
    	String uri = APIEndpoints.REQUEST_TOKEN_PATH;
    	HttpGet getMethod = this.buildConsumerSignedHttpGetWithQueryString(uri, parameters);
    	if (requestHeaders != null)
    	{
    		for (String header : requestHeaders.keySet())
    		{
    			getMethod.addHeader(header, requestHeaders.get(header));
    		}
    	}
    	NetflixAPIResponse response = this.netflixAPIClient.executeCustomMethod(getMethod);
    	if (logger.isDebugEnabled())
    	{
    		logger.debug(response.getResponseBody());
    	}
    	token = new OAuthRequestToken(response.getResponseBody());
    	return token;
    }
    
	/**
	 * The second major step in the OAuth flow. <br />
     * Sends the request token off to the service provider, on behalf of the
     * customer, so the customer can authenticate the request token.  This call
     * does not alter the request token itself; rather it affects the back-end server's
     * state.  The request token should then be exchangeable for an access token.
     * @param requestToken
     */
    private void authorizeRequestToken(OAuthRequestToken requestToken, NetflixAPICustomer customer) throws Exception
	{
    	Map<String, String> parameters = new HashMap<String, String>();
    	parameters.put("oauth_token", requestToken.getTokenText());
    	parameters.put("oauth_consumer_key", this.netflixAPIClient.getConsumerKey());
    	parameters.put("application_name", requestToken.getApplicationName());
    	parameters.put("name", customer.getUsername());
    	parameters.put("password", customer.getPassword());
    	parameters.put("accept_tos", "true");
    	parameters.put("output", "pox");
    	parameters.put("oauth_callback", "");
    	
    	HttpPost loginMethod = this.buildLoginMethod(createURIWithQueryString(APIEndpoints.LOGIN_PATH, parameters));
    	
    	HttpResponse httpResponse = httpClient.execute(loginMethod);
    	
    	if (logger.isDebugEnabled())
    	{
    		logger.debug("Response from authorize token: " + EntityUtils.toString(httpResponse.getEntity()));
    	}
    	if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
    		throw new NetflixAPIException(NetflixAPIException.LOGIN_FAILED);
	}
    
    /**
     * Builds a POST method specific to logging a user in.
     * @param uri
     * @param parameters
     * @return
     */
    private HttpPost buildLoginMethod(String uri)
	{
    	HttpPost method = this.newHttpPost(uri);
    	
    	if (logger.isDebugEnabled())
    	{
    		String message = "Created method [ POST " + uri + "]";
    		logger.debug(message);
    	}
    	
    	return method;
    }
    
	/**
     * The third major step in the OAuth flow. <br />
     * Exchanges the now-authorized request token for an access token.
     * Aren't you happy now?
     * @param authorizedRequestToken
     * @return
     */
    public OAuthAccessToken exchangeRequestForAccessToken(OAuthRequestToken authorizedRequestToken) throws Exception
	{
    	return this.exchangeRequestForAccessToken(authorizedRequestToken, null);
	}
    
    /**
     * The third major step in the OAuth flow. <br />
     * Exchanges the now-authorized request token for an access token.
     * Aren't you happy now?
     * @param authorizedRequestToken
     * @return
     */
    public OAuthAccessToken exchangeRequestForAccessToken(OAuthRequestToken authorizedRequestToken, Map<String, String> requestHeaders) throws Exception
	{
    	OAuthAccessToken oat = null;
    	int statusCode = 0;
    	String uri = APIEndpoints.ACCESS_TOKEN_PATH;
    	Map<String, String> parameters = this.getDefaultOAuthParameters();
    	parameters.put("oauth_token", authorizedRequestToken.getTokenText());
    	
    	HttpGet exchangeMethod = this.buildAccessTokenRequestMethod(uri, parameters, authorizedRequestToken);
    	if (requestHeaders != null)
    	{
    		for (String header : requestHeaders.keySet())
    		{
    			exchangeMethod.setHeader(header, requestHeaders.get(header));
    		}
    	}
    	
    	HttpResponse httpResponse = httpClient.execute(exchangeMethod);
    	String response = EntityUtils.toString(httpResponse.getEntity());
    	statusCode = httpResponse.getStatusLine().getStatusCode();
    	if (statusCode != HttpStatus.SC_OK)
    	{
    		String message = "Exchange of request token [ " + authorizedRequestToken.getTokenText() + " ] FAILED with " +
    				"response [ " + response + " ]";
    		logger.error(message);
    		oat = new OAuthAccessToken();
    		oat.setErrorCause(message);
    		return oat;
    	}
    	
    	if (logger.isDebugEnabled())
    	{
    		logger.debug("Response from exchange token: " + response);
    	}
    	oat = new OAuthAccessToken(response);
 		return oat; 
	}
    
	/**
	 * Creates the Authorization: header in the OAuth realm for 
	 * API requests.
	 * @param params
	 * @return - string containing oauth realm info.
	 */
	public String createAuthorizationHeader(Map<String, String> params)
	{
		boolean isFirstParam = true;
		StringBuilder sb = new StringBuilder();
		sb.append("OAuth ");
		for (String param : params.keySet())
		{
			if (isFirstParam == true)
				isFirstParam = false;
				
			String paramVal = params.get(param);
			if (paramVal != null && param.startsWith("oauth"))
			{
				if (!isFirstParam) sb.append(",");
				sb.append(param).append("=\"").append(OAuth.percentEncode(paramVal)).append("\"");
			}
		}
		return sb.toString();
	}
	
	/**
	 * Filters the OAuth-specific from the arbitrary parameters.
	 * @param method
	 * @param parameters
	 */
	public Map<String, String> withoutOauthParams(Map<String, String> parameters) {
		Map<String, String> result = new HashMap<String, String>();
		for (Entry<String, String> e : parameters.entrySet()) {
			if (!e.getKey().startsWith("oauth")) {
				result.put(e.getKey(), e.getValue());
			}
		}
		return result;
	}
	
	private String createURIWithQueryString(String uri, Map<String, String> params) throws Exception {
		String query = createNormalizedQueryString(params);
		if (query.length() > 0) {
			return uri + "?" + query;
		} else {
			return uri;
		}
	}
	
	/**
	 * Creates query string for GET requests.
	 * @param params
	 * @return - string containing oauth realm info.
	 */
	protected String createNormalizedQueryString(Map<String, String> params) throws Exception
	{
		Set<String> keySet = params.keySet();
		String[] keys = new String[keySet.size()];
		keySet.toArray(keys);
		Arrays.sort(keys);
		
		boolean isFirstParam = true;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < keys.length; i++)
		{
			if (isFirstParam == true)
				isFirstParam = false;
			else
				sb.append("&");
			String paramVal = params.get(keys[i]);
			if (paramVal != null)
				sb.append(keys[i]).append("=").append(URLEncoder.encode(paramVal, "UTF-8"));
		}
		return sb.toString();
	}
	
	/**
	 * Creates query string for GET requests.
	 * @param params
	 * @return - string containing oauth realm info.
	 */
	protected String createNonOAuthQueryString(Map<String, String> params) throws Exception
	{
		Set<String> keySet = params.keySet();
		String[] keys = new String[keySet.size()];
		keySet.toArray(keys);
		Arrays.sort(keys);
		
		boolean isFirstParam = true;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < keys.length; i++)
		{
			if (isFirstParam == true)
				isFirstParam = false;
				
			String paramVal = params.get(keys[i]);
			if (paramVal != null && !(keys[i].startsWith("oauth")))
			{
				if (!isFirstParam) sb.append("&");
				sb.append(keys[i]).append("=").append(URLEncoder.encode(paramVal, "UTF-8"));
			}
		}
		return sb.toString();
	}
	
	/**
	 * Creates an HttpMethod object with default settings
	 * (Ignores cookies and doesn't follow redirects).
	 * @param uri
	 * @return - defualt HttpMethod
	 */
	private HttpGet newHttpGet(String uri)
    {
        HttpGet method = new HttpGet(uri);
        HttpParams params = method.getParams();
        HttpClientParams.setCookiePolicy(params, CookiePolicy.IGNORE_COOKIES);
        HttpClientParams.setRedirecting(params, false);
        return method;
    }
	
	/**
	 * Creates an HttpPost object with default settings
	 * (Ignores cookies and doesn't follow redirects).
	 * @param uri
	 * @return - defualt HttpMethod
	 */
	private HttpPost newHttpPost(String uri)
    {
        HttpPost method = new HttpPost(uri);
        HttpParams params = method.getParams();
        HttpClientParams.setCookiePolicy(params, CookiePolicy.IGNORE_COOKIES);
        HttpClientParams.setRedirecting(params, false);
        return method;
    }
	
	/**
	 * Creates an HttpPost object with default settings
	 * (Ignores cookies and doesn't follow redirects).
	 * @param uri
	 * @return - defualt HttpMethod
	 */
	private HttpDelete newHttpDelete(String uri)
    {
        HttpDelete method = new HttpDelete(uri);
        HttpParams params = method.getParams();
        HttpClientParams.setCookiePolicy(params, CookiePolicy.IGNORE_COOKIES);
        HttpClientParams.setRedirecting(params, false);
        return method;
    }
	
	/**
	 * @param method
	 * @param requestHeaders
	 */
	private HttpRequestBase applyRequestHeadersToMethod(HttpRequestBase method, Map<String, String> requestHeaders)
	{
		for (String header : requestHeaders.keySet())
		{
			method.setHeader(header, requestHeaders.get(header));
		}
		return method;
	}
	
}
