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

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.unitime.timetable.defaults.ApplicationProperty;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SpringOAuth2AuthenticationProvider extends LdapAuthenticationProvider {
	private static Log sLog = LogFactory.getLog(SpringOAuth2AuthenticationProvider.class);

	
	public SpringOAuth2AuthenticationProvider(LdapAuthenticator authenticator) {
		super(authenticator);
	}
	
	public SpringOAuth2AuthenticationProvider(LdapAuthenticator authenticator, LdapAuthoritiesPopulator authoritiesPopulator) {
		super(authenticator, authoritiesPopulator);
	}

	@Override
    protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken authentication) {
		sLog.info("TREVOR CLARIDGE: doAuthentication() oauth2 provider ");

		if (ApplicationProperty.AuthenticationLdapUrl.defaultValue().equals(ApplicationProperty.AuthenticationLdapUrl.value()))
			throw new BadCredentialsException("OAuth2 authentication is not configured.");
		return super.doAuthentication(authentication);
	}

}
