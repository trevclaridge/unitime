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
        authentication.setAuthenticated(true);

        return authentication;
    }

    public boolean supports(java.lang.Class<?> authentication) {
        sLog.info("TREVOR CLARIDGE: supports() TrevorAuthentication.");

        return true;
    }
}
