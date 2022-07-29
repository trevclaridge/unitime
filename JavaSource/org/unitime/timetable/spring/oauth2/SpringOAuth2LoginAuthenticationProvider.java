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


public class SpringOAuth2LoginAuthenticationProvider extends OAuth2LoginAuthenticationProvider {
	private static Log sLog = LogFactory.getLog(SpringOAuth2LoginAuthenticationProvider.class);

	
	public SpringOAuth2LoginAuthenticationProvider(OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient, OAuth2UserService<OAuth2UserRequest,OAuth2User> userService) {
		super(authenticator);
	}

	@Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		sLog.info("TREVOR CLARIDGE: doAuthentication() oauth2 provider ");

		if (ApplicationProperty.AuthenticationLdapUrl.defaultValue().equals(ApplicationProperty.AuthenticationLdapUrl.value()))
			throw new BadCredentialsException("OAuth2 authentication is not configured.");
		return super.authenticate(authentication);
	}

}
