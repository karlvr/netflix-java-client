package com.netflix.api.client.dal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.api.NetflixAPIException;
import com.netflix.api.client.NetflixAPIClient;
import com.netflix.api.client.NetflixAPICustomer;
import com.netflix.api.client.oauth.OAuthAccessToken;

/**
 * 
 * @author John Haren
 */
public class MethodBuilderTest
{
	private static NetflixAPIClient client;
	
	private static HttpMethodBuilder builder;
	
	@Test
	public void checkDefaultSignatureMethod()
	{
		Map<String, String> params = builder.getDefaultOAuthParameters();
		assertEquals("oauth signature method not HMAC-SHA1", "HMAC-SHA1", params.get("oauth_signature_method"));
	}
	
	@Test
	public void checkDefaultOAuthVersion()
	{
		Map<String, String> params = builder.getDefaultOAuthParameters();
		assertEquals("oauth version not 1.0", "1.0", params.get("oauth_version"));
	}
	
	@Test
	public void checkConsumerKey()
	{
		Map<String, String> params = builder.getDefaultOAuthParameters();
		assertEquals("Consumer key got mangled", "foo", params.get("oauth_consumer_key"));
	}
	
	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildConsumerKeyedGetMethod(java.lang.String, java.util.Map)}.
	 */
	@Test
	public void testBuildConsumerKeyedGetMethod()
	{
		HttpGet method;
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildConsumerKeyedHttpGet(uri, parameters);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildConsumerSignedGetMethod(java.lang.String, java.util.Map)}.
	 */
	@Test
	public void testBuildConsumerSignedGetMethod()
	{
		HttpGet method;
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildConsumerKeyedHttpGet(uri, parameters);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildConsumerSignedGetMethodWithQueryString(java.lang.String, java.util.Map)}.
	 */
	@Test
	public void testBuildConsumerSignedGetMethodWithQueryString()
	{
		HttpGet method;
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildConsumerSignedHttpGetWithQueryString(uri, parameters);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildConsumerSignedPostMethod(java.lang.String, java.util.Map)}.
	 */
	@Test
	public void testBuildConsumerSignedPostMethod()
	{
		HttpPost method;
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildConsumerSignedHttpPost(uri, parameters);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildCustomerAuthorizedGetMethod(java.lang.String, java.util.Map, com.netflix.api.client.NetflixAPICustomer)}.
	 */
	@Test
	public void testBuildCustomerAuthorizedGetMethod()
	{
		HttpGet method;
		NetflixAPICustomer customer = new NetflixAPICustomer("foo", "bar");
		OAuthAccessToken token = new OAuthAccessToken("oauth_token=foo&user_id=whee&oauth_token_secret=quietitsasecret");
		customer.setAccessToken(token);
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildCustomerAuthorizedHttpGet(uri, parameters, customer);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildCustomerAuthorizedPostMethod(java.lang.String, java.util.Map, com.netflix.api.client.NetflixAPICustomer)}.
	 */
	@Test
	public void testBuildCustomerAuthorizedPostMethod()
	{
		HttpPost method;
		NetflixAPICustomer customer = new NetflixAPICustomer("foo", "bar");
		OAuthAccessToken token = new OAuthAccessToken("oauth_token=foo&user_id=whee&oauth_token_secret=quietitsasecret");
		customer.setAccessToken(token);
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildCustomerAuthorizedHttpPost(uri, parameters, customer);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildCustomerAuthorizedDeleteMethod(java.lang.String, java.util.Map, com.netflix.api.client.NetflixAPICustomer)}.
	 */
	@Test
	public void testBuildCustomerAuthorizedDeleteMethod()
	{
		HttpDelete method;
		NetflixAPICustomer customer = new NetflixAPICustomer("biz", "baz");
		OAuthAccessToken token = new OAuthAccessToken("oauth_token=foo&user_id=whee&oauth_token_secret=quietitsasecret");
		customer.setAccessToken(token);
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			method = builder.buildCustomerAuthorizedHttpDelete(uri, parameters, customer);
			assertNotNull("Got bupkis back from builder", method);
		}
		catch (Exception e)
		{
			fail(e.toString());
		}
	}
	
	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#buildCustomerAuthorizedGetMethod(java.lang.String, java.util.Map, com.netflix.api.client.NetflixAPICustomer)}.
	 */
	@Test
	public void testFailBuildCustomerAuthorizedGetMethodWithNoAccessToken()
	{
		NetflixAPICustomer customer = new NetflixAPICustomer("foo", "bar");
		String uri = "http://foo.com";
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		try
		{
			builder.buildCustomerAuthorizedHttpGet(uri, parameters, customer);
		}
		catch (Exception e)
		{
			assertTrue("Should catch a NetflixAPIException.", e instanceof NetflixAPIException);
			assertEquals("Customer has no access token.", e.getMessage());
			return;
		}
		fail("Exception should have been thrown by call to buildCustomerAuthorizedGetMethod.");
	}

	/**
	 * Test method for {@link com.netflix.api.client.dal.HttpMethodBuilder#createAuthorizationHeader(java.util.HashMap)}.
	 */
	@Test
	public void testCreateAuthorizationHeader()
	{
		Map<String, String> parameters = builder.getDefaultOAuthParameters();
		String authHeader = builder.createAuthorizationHeader((HashMap<String, String>) parameters);
		
		assertNotNull("Authorization header creation failed.", authHeader);
	}

	@BeforeClass
	public static void beforeClass()
	{
		client = new NetflixAPIClient("foo", "bar");
		builder = new HttpMethodBuilder(client);
	}
	
}
