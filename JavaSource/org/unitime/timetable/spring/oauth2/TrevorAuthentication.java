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

import org.apache.http.client.methods.HttpPost;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64.Decoder;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;

import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;

import java.io.InputStream;
import java.lang.Exception;
import org.apache.http.NameValuePair;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import io.jsonwebtoken.SignatureAlgorithm;
import javax.crypto.spec.SecretKeySpec;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;

import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationStatus;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.unitime.timetable.security.context.UniTimeUserContext;
import org.unitime.timetable.security.authority.RoleAuthority;
import org.unitime.timetable.model.Roles;
import org.unitime.timetable.model.dao.TimetableManagerDAO;
import org.unitime.timetable.model.Session;
import org.unitime.timetable.security.context.AnonymousUserContext;
import org.unitime.timetable.security.UserAuthority;
import org.unitime.timetable.security.UserContext;



public class TrevorAuthentication implements AuthenticationProvider {
	private static Log sLog = LogFactory.getLog(TrevorAuthentication.class);


	public TrevorAuthentication() {
		sLog.info("TREVOR CLARIDGE: TrevorAuthentication.");
	}

	// @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		sLog.info("TREVOR CLARIDGE: authenticate() TrevorAuthentication.");
        sLog.info("details: " + authentication.getDetails().toString());
        sLog.info("credentials: " + authentication.getCredentials().toString());
        sLog.info("principal: " + authentication.getPrincipal().toString());

        sLog.info(ApplicationProperty.AuthenticationOAuth2RedirectUrl.value());
        String authCode = authentication.getCredentials().toString();
        String username = authentication.getPrincipal().toString();

        if (username.equals("OAuth2")) {
            String token = postCodeForToken(authCode);
            JsonObject tokenDecoded = decodeAndVerifyJWT(token);

            // "scp": "email openid profile"
            // read above line from tokenDecoded
            List<OpenIDAttribute> attributes = new ArrayList<>();
            // https://docs.spring.io/spring-security/site/docs/4.0.x/apidocs/org/springframework/security/openid/OpenIDAttribute.html
            // name, type(uri)
            attributes.add(new OpenIDAttribute("email", "?"));
            attributes.add(new OpenIDAttribute("openid", "?"));
            attributes.add(new OpenIDAttribute("profile", "?"));

            Set<UserAuthority> authorities = new HashSet<UserAuthority>();
            // Map<String,Object> testAuthority = new HashMap<>();
            // testAuthority.put("test", "test again");
        
            // org.hibernate.Session hibSession = TimetableManagerDAO.getInstance().createNewSession();
            // Roles anonRole = Roles.getRole(Roles.ROLE_ANONYMOUS, hibSession);
            // authorities.add(new RoleAuthority(-1l, anonRole));
            // Roles studentRole = Roles.getRole(Roles.ROLE_STUDENT, hibSession);
            // authorities.add(new RoleAuthority(1l, studentRole));

            UserContext oauth2UserContext = new OAuth2UserContext(tokenDecoded.get("upn").getAsString(), tokenDecoded.get("name").getAsString());
            UserContext unitimeUserContextExternalID = new UniTimeUserContext(tokenDecoded.get("upn").getAsString(), tokenDecoded.get("given_name").getAsString() + "." + tokenDecoded.get("family_name").getAsString(), null, tokenDecoded.get("family_name").getAsString());
            // UserContext unitimeUserContextExternalID = new UniTimeUserContext(tokenDecoded.get("upn").getAsString(), tokenDecoded.get("name").getAsString(), null, tokenDecoded.get("family_name").getAsString());
            // sLog.info("unitimeUserContext authorities: " + unitimeUserContext.getAuthorities().toString());
            sLog.info("unitimeUserContextExternalID authorities: " + unitimeUserContextExternalID.getAuthorities().toString());
            sLog.info("oauth2UserContext authorities: " + oauth2UserContext.getAuthorities().toString());

            // OpenIDAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities, String identityUrl, List<OpenIDAttribute> attributes)
            Authentication authenticationOpenID = new OpenIDAuthenticationToken(unitimeUserContextExternalID, unitimeUserContextExternalID.getAuthorities(), "no idea here either", attributes);
       
            return authenticationOpenID;
        } else {
            Authentication authenticationNative = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials());
            sLog.info(authenticationNative.isAuthenticated() ? "native is authenticated" : "native is NOT authenticated");
            sLog.info(authenticationNative.getAuthorities().toString());

            return authenticationNative;
        }
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
        // ApplicationProperty.AuthenticationLdapUrl.value()
        urlParameters.add(new BasicNameValuePair("client_id", "98ae7ee1-eb75-4a49-a7c0-c7074eb64e02"));
        urlParameters.add(new BasicNameValuePair("scope", "openid"));
        urlParameters.add(new BasicNameValuePair("code", code));
        urlParameters.add(new BasicNameValuePair("redirect_uri", "https://unitime-ssotest.wallawalla.edu/UniTime/selectPrimaryRole.do"));
        urlParameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        urlParameters.add(new BasicNameValuePair("client_secret", System.getenv("UniTime_Secret")));

        try {
            post.setEntity(new UrlEncodedFormEntity(urlParameters));
        } catch(Exception e) {
            sLog.info("set entity error: " + e.toString());
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(post)) {
            
            Gson gson = new Gson();
            // sLog.info(EntityUtils.toString(response.getEntity()));
            JsonObject body = gson.fromJson(EntityUtils.toString(response.getEntity()), JsonObject.class);
            String accessToken = body.get("access_token").getAsString();
            String idToken = body.get("id_token").getAsString();
            // sLog.info("ACCESS_TOKEN: " +  accessToken);
            // sLog.info("ID_TOKEN: " +  idToken);
            return accessToken;
        } catch(Exception e) {
            sLog.info("post error: " + e.toString());
        }  

        try {
            httpClientMaster.close();
        } catch(Exception e) {
            sLog.info("http close error: " + e.toString());
        }

        return null;
    }

    private JsonObject decodeAndVerifyJWT(String token) {
        // https://www.baeldung.com/java-jwt-token-decode
        String publicKey = "MIIDBTCCAe2gAwIBAgIQH4FlYNA+UJlF0G3vy9ZrhTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMDUyMjIwMDI0OVoXDTI3MDUyMjIwMDI0OVowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBDDCbY/cjEHfEEulZ5ud/CuRjdT6/yN9fy1JffjgmLvvfw6w7zxo1YkCvZDogowX8qqAC/qQXnJ/fl12kvguMWU59WUcPvhhC2m7qNLvlOq90yo+NsRQxD/v0eUaThrIaAveZayolObXroZ+HwTN130dhgdHVTHKczd4ePtDjLwSv/2a/bZEAlPys102zQo8gO8m7W6/NzRfZNyo6U8jsmNkvqrxW2PgKKjIS/UafK9hwY/767K+kV+hnokscY2xMwxQNlSHEim0h72zQRHltioy15M+kBti4ys+V7GC6epL//pPZT0Acv1ewouGZIQDfuo9UtSnKufGi26dMAzSkCAwEAAaMhMB8wHQYDVR0OBBYEFLFr+sjUQ+IdzGh3eaDkzue2qkTZMA0GCSqGSIb3DQEBCwUAA4IBAQCiVN2A6ErzBinGYafC7vFv5u1QD6nbvY32A8KycJwKWy1sa83CbLFbFi92SGkKyPZqMzVyQcF5aaRZpkPGqjhzM+iEfsR2RIf+/noZBlR/esINfBhk4oBruj7SY+kPjYzV03NeY0cfO4JEf6kXpCqRCgp9VDRM44GD8mUV/ooN+XZVFIWs5Gai8FGZX9H8ZSgkIKbxMbVOhisMqNhhp5U3fT7VPsl94rilJ8gKXP/KBbpldrfmOAdVDgUC+MHw3sSXSt+VnorB4DU4mUQLcMriQmbXdQc8d1HUZYZEkcKaSgbygHLtByOJF44XUsBotsTfZ4i/zVjnYcjgUQmwmAWD";

        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        String signature = new String(chunks[2]);


        Gson gson = new Gson();
        JsonObject body = gson.fromJson(payload, JsonObject.class);
        String upn = body.get("upn").getAsString();
        String name = body.get("name").getAsString();

        sLog.info("UPN: " + upn);
        sLog.info("name: " + name);

        String tokenWithoutSignature = chunks[1] + "." + chunks[0];
            
        SignatureAlgorithm sa = SignatureAlgorithm.HS256;
        SecretKeySpec secretKeySpec = new SecretKeySpec(publicKey.getBytes(), sa.getJcaName());
        DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, secretKeySpec);

        if (!validator.isValid(tokenWithoutSignature, signature)) {
            sLog.info("signature not valid");
        }
        
        return body;
    }
}
