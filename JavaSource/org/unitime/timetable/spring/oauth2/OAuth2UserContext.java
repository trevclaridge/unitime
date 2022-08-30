package org.unitime.timetable.spring.oauth2;

import org.unitime.timetable.security.context.AbstractUserContext;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TreeSet;

import org.unitime.localization.impl.Localization;
import org.unitime.timetable.defaults.ApplicationProperty;
import org.unitime.timetable.defaults.UserProperty;
import org.unitime.timetable.model.Advisor;
import org.unitime.timetable.model.Department;
import org.unitime.timetable.model.DepartmentalInstructor;
import org.unitime.timetable.model.ManagerRole;
import org.unitime.timetable.model.ManagerSettings;
import org.unitime.timetable.model.Roles;
import org.unitime.timetable.model.Session;
import org.unitime.timetable.model.Settings;
import org.unitime.timetable.model.SolverGroup;
import org.unitime.timetable.model.Student;
import org.unitime.timetable.model.TimetableManager;
import org.unitime.timetable.model.UserData;
import org.unitime.timetable.model.dao.SessionDAO;
import org.unitime.timetable.model.dao.TimetableManagerDAO;
import org.unitime.timetable.model.dao.UserDataDAO;
import org.unitime.timetable.security.UserAuthority;
import org.unitime.timetable.security.authority.RoleAuthority;
import org.unitime.timetable.security.qualifiers.SimpleQualifier;
import org.unitime.timetable.security.rights.HasRights;
import org.unitime.timetable.security.rights.Right;
import org.unitime.timetable.util.LoginManager;

public class OAuth2UserContext extends AbstractUserContext {
    private static final long serialVersionUID = 1L;
    private String iId, iName; String iEmail;

    protected OAuth2UserContext(String upn, String name) {
        iId = upn;
        iName = name;
    }


	public OAuth2UserContext(TimetableManager manager, Session session) {
		iId = manager.getExternalUniqueId();
		iName = manager.getName();
		iEmail = manager.getEmailAddress();
		for (ManagerRole role: manager.getManagerRoles()) {
			if (!role.getRole().isEnabled()) continue;
			
			boolean hasSession = false;
			for (Department department: manager.getDepartments())
				if (session.equals(department.getSession())) { hasSession = true; break; }

			if (role.getRole().hasRight(Right.SessionIndependent)) {
			} else if (role.getRole().hasRight(Right.SessionIndependentIfNoSessionGiven)) {
				if (!hasSession && !manager.getDepartments().isEmpty()) continue;
			} else {
				if (!hasSession) continue;
			}
			
			UserAuthority authority = new RoleAuthority(manager.getUniqueId(), role.getRole());
			authority.addQualifier(session);
			authority.addQualifier(manager);
			for (Department department: manager.getDepartments())
				if (department.getSession().equals(session))
					authority.addQualifier(department);
			for (SolverGroup group: manager.getSolverGroups())
				for (Department department: group.getDepartments())
					if (department.getSession().equals(session)) {
						authority.addQualifier(group); break;
					}
			addAuthority(authority);
			if (getCurrentAuthority() == null || role.isPrimary())
				setCurrentAuthority(authority);
		}
	}

    @Override
	public void setProperty(String key, String value) {
		if (value != null && value.isEmpty()) value = null;
		super.setProperty(key, value);
		if (getExternalUserId() == null || getExternalUserId().isEmpty()) return;
		org.hibernate.Session hibSession = UserDataDAO.getInstance().createNewSession();
		try {
			Settings settings = (Settings)hibSession.createQuery("from Settings where key = :key")
					.setString("key", key).setCacheable(true).setMaxResults(1).uniqueResult();
			
			if (settings != null && getCurrentAuthority() != null && !getCurrentAuthority().getQualifiers("TimetableManager").isEmpty()) {
				ManagerSettings managerData = (ManagerSettings)hibSession.createQuery(
						"from ManagerSettings where key.key = :key and manager.externalUniqueId = :id")
						.setString("key", key).setString("id", getExternalUserId()).setCacheable(true).setMaxResults(1).uniqueResult();
				
				if (value == null && managerData == null) return;
				if (value != null && managerData != null && value.equals(managerData.getValue())) return;
				
				if (managerData == null) {
					managerData = new ManagerSettings();
					managerData.setKey(settings);
					managerData.setManager(TimetableManagerDAO.getInstance().get((Long)getCurrentAuthority().getQualifiers("TimetableManager").get(0).getQualifierId(), hibSession));
				}
				managerData.setValue(value);
				
				if (value == null)
					hibSession.delete(managerData);
				else
					hibSession.saveOrUpdate(managerData);
			} else {
				UserData userData = UserDataDAO.getInstance().get(new UserData(getExternalUserId(), key), hibSession);
				if (userData == null && value == null) return;
				if (userData != null && value != null && value.equals(userData.getValue())) return;
				
				if (userData == null)
					userData = new UserData(getExternalUserId(), key);
				
				if (value == null) {
					hibSession.delete(userData);
				} else {
					userData.setValue(value);
					hibSession.saveOrUpdate(userData);
				}
			}
			hibSession.flush();
		} finally {
			hibSession.close();
		}
	}
    
    public static Session defaultSession(TreeSet<Session> sessions, HasRights role, String primaryCampus) {
		if (sessions==null || sessions.isEmpty()) return null; // no session -> no default
		
		//try to pick among active sessions first (check that all active sessions are of the same initiative)
        String initiative = null;
        Session lastActive = null;
        Session currentActive = null;
        Session firstFutureSession = null;
        boolean multipleInitiatives = false;
        
		Calendar cal = Calendar.getInstance(Localization.getJavaLocale());
		cal.set(Calendar.HOUR_OF_DAY, 0);
		cal.set(Calendar.MINUTE, 0);
		cal.set(Calendar.SECOND, 0);
		cal.set(Calendar.MILLISECOND, 0);
		Integer shift = ApplicationProperty.SessionDefaultShiftDays.intValue();
		if (shift != null && shift.intValue() != 0)
			cal.add(Calendar.DAY_OF_YEAR, shift);
		Date today = cal.getTime();

        for (Session session: sessions) {
            if (session.getStatusType() == null || !session.getStatusType().isActive() || session.getStatusType().isTestSession()) continue;
            if (initiative==null)
            	initiative = session.getAcademicInitiative();
            else if (!initiative.equals(session.getAcademicInitiative())) {
            	if (initiative.equals(primaryCampus)) {
            		continue; // skip other campuses
            	} else if (session.getAcademicInitiative().equals(primaryCampus)) {
            		initiative = session.getAcademicInitiative();
            		currentActive = null;
            		firstFutureSession = null;
            		lastActive = null;
            	} else {
            		multipleInitiatives = true;
            		currentActive = null;
            		firstFutureSession = null;
            		lastActive = null;
            		continue;
            	}
            }
            
            Date begin = session.getEventBeginDate();
			cal.setTime(session.getEventEndDate());
			cal.add(Calendar.DAY_OF_YEAR, 1);
			Date end = cal.getTime();
            
            if (currentActive == null && !begin.after(today) && today.before(end))
            	currentActive = session;
            
            if (currentActive != null && firstFutureSession == null && !currentActive.equals(session))
            	firstFutureSession = session;

            if (currentActive == null && firstFutureSession == null && today.before(begin))
            	firstFutureSession = session;

            lastActive = session;
        }
        
        // multiple initiatives & no matching primary -> no default
        if (multipleInitiatives && lastActive == null) return null;
        
        if (role != null && role.hasRight(Right.SessionDefaultFirstFuture)) {
        	if (firstFutureSession != null) return firstFutureSession;
        	if (currentActive != null) return currentActive;
        }
        
        if (role != null && role.hasRight(Right.SessionDefaultFirstExamination)) {
        	if (currentActive != null && !currentActive.getStatusType().canNoRoleReportExamFinal()) return currentActive;
        	if (firstFutureSession != null) return firstFutureSession;
        }
        
        if (currentActive != null) return currentActive;
        if (firstFutureSession != null) return firstFutureSession;
        if (lastActive != null) return lastActive;
        
        Session lastNoTest = null;
        for (Session session: sessions) {
        	if (session.getStatusType() == null || session.getStatusType().isTestSession()) continue;
        	
        	Date begin = session.getEventBeginDate();
        	if (!begin.after(today)) return session;
        	
        	lastNoTest = session;
        }
        return lastNoTest;
	}

    @Override
	public void setCurrentAuthority(UserAuthority authority) {
		super.setCurrentAuthority(authority);
		if (authority.getAcademicSession() != null)
			setProperty(UserProperty.LastAcademicSession, authority.getAcademicSession().getQualifierId().toString());
	}

    @Override
	public String getName() { return iName; }
    
    @Override
	public String getEmail() { return iId; }
    
    @Override
	public String getExternalUserId() { return iId; }

    @Override
	public String getPassword() { return null; }
    
    @Override
	public String getUsername() { return iName; }


    @Override
	public boolean isAccountNonLocked() { return !LoginManager.isUserLockedOut(getUsername(), new Date()); }
}