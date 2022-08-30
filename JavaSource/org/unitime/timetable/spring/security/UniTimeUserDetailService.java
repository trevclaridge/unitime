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
package org.unitime.timetable.spring.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.unitime.timetable.model.User;
import org.unitime.timetable.model.dao.UserDAO;
import org.unitime.timetable.security.context.UniTimeUserContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author Tomas Muller
 */
@Service("unitimeUserDetailsService")
public class UniTimeUserDetailService implements UserDetailsService {
	private static Log sLog = LogFactory.getLog(UniTimeUserDetailService.class);

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		org.hibernate.Session hibSession = UserDAO.getInstance().createNewSession();
		try {
			User user = (User) hibSession.createQuery("from User where username=:userName")
					.setString("userName", username).setMaxResults(1).uniqueResult();

			if (user == null)
				throw new UsernameNotFoundException("User " + username + " is not known.");

			UserDetails userDetails =  new UniTimeUserContext(user.getExternalUniqueId(), user.getUsername(), null, user.getPassword());
			sLog.info("userDetails authorities: " + userDetails.getAuthorities().toString());	
			return userDetails;	
		} finally {
			hibSession.close();
		}
	}

}
