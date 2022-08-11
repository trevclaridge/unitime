/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * The Apereo Foundation licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
*/
package org.unitime.timetable.spring.oauth2;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.unitime.timetable.defaults.ApplicationProperty;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.google.gwt.user.client.Window;

import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.openid.OpenIDAuthenticationToken;
// import java.net.http.HttpClient;
import org.apache.http.client.methods.HttpPost;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64.Decoder;
import java.util.Base64;
import java.util.Collections;
// import org.omg.DynamicAny.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
// import java.net.http.HttpResponse;
import java.io.InputStream;
import java.lang.Exception;
// import org.apache.hc.client5.http.classic.methods.HttpPost;
// import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
// import org.apache.hc.core5.http.HttpEntity;
// import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.http.NameValuePair;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

// import javax.json.JSONObject;
// import javax.json.JSONString;
// import org.json.simple.JSONObject;
// import jakarta.json.JsonObject;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import io.jsonwebtoken.SignatureAlgorithm;
import javax.crypto.spec.SecretKeySpec;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;

public class TrevorAuthentication implements AuthenticationProvider {
	private static Log sLog = LogFactory.getLog(TrevorAuthentication.class);


	public TrevorAuthentication() {
		sLog.info("TREVOR CLARIDGE: TrevorAuthentication.");
	}

	// @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		sLog.info("TREVOR CLARIDGE: authenticate() TrevorAuthentication.");
        // sLog.info(authentication.getDetails().toString());
        String testPassword = authentication.getCredentials().toString();
        String authCode = authentication.getPrincipal().toString();
        sLog.info("test password : " + testPassword);
        sLog.info("authcode: " + authCode);

        
        String token = postCodeForToken(authCode);
        decodeAndVerifyJWT(token);

        // OpenIDAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities, String identityUrl, List<OpenIDAttribute> attributes)
        Authentication authenticationNew = new OpenIDAuthenticationToken("myPrincipal", Collections.EMPTY_LIST, "identityUrl", Collections.EMPTY_LIST);
        sLog.info(authenticationNew.isAuthenticated() ? "is authenticated" : "is NOT authenticated");
        return authenticationNew;
    }

    public boolean supports(java.lang.Class<?> authentication) {
        sLog.info("TREVOR CLARIDGE: supports() TrevorAuthentication.");

        return true;
    }

    private String postCodeForToken(String code) {
        // https://mkyong.com/java/how-to-send-http-request-getpost-in-java/
        CloseableHttpClient httpClientMaster = HttpClients.createDefault();
        HttpPost post = new HttpPost("https://login.microsoftonline.com/d958f048-e431-4277-9c8d-ebfb75e7aa64/oauth2/v2.0/token");

        // add request parameter, form parameters
        List<NameValuePair> urlParameters = new ArrayList<>();
        urlParameters.add(new BasicNameValuePair("client_id", "98ae7ee1-eb75-4a49-a7c0-c7074eb64e02"));
        urlParameters.add(new BasicNameValuePair("scope", "openid"));
        urlParameters.add(new BasicNameValuePair("code", code));
        urlParameters.add(new BasicNameValuePair("redirect_uri", "https://unitime-ssotest.wallawalla.edu/UniTime/selectPrimaryRole.do"));
        urlParameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        // urlParameters.add(new BasicNameValuePair("client_secret", "TODO"));

        try {
            post.setEntity(new UrlEncodedFormEntity(urlParameters));
        } catch(Exception e) {
            sLog.info(e.toString());
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(post)) {
            
            Gson gson = new Gson();
            JsonObject body = gson.fromJson(EntityUtils.toString(response.getEntity()), JsonObject.class);
            String token = body.get("error").getAsString();
            sLog.info("TOKEN: " +  token);
            return token;
        } catch(Exception e) {
            sLog.info(e.toString());
        }  

        try {
            httpClientMaster.close();
        } catch(Exception e) {
            sLog.info(e.toString());
        }

        return null;
    }

    private void decodeAndVerifyJWT(String token) {
        // https://www.baeldung.com/java-jwt-token-decode
        String testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String secretKey = "your-256-bit-secret";


        String[] chunks = testToken.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        String signature = new String(chunks[2]);

        sLog.info("Header: " + header);
        sLog.info("Payload: " + payload);
        sLog.info("Signature: " + signature);

        String tokenWithoutSignature = chunks[1] + "." + chunks[0];
            
        SignatureAlgorithm sa = SignatureAlgorithm.HS256;
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());
        DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, secretKeySpec);

        if (!validator.isValid(tokenWithoutSignature, signature)) {
            sLog.info("signature not valid");
        }
    }
}
