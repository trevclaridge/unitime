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
package org.unitime.timetable.test;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Hashtable;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cpsolver.coursett.TimetableXMLLoader.DatePattern;
import org.cpsolver.coursett.model.Lecture;
import org.cpsolver.coursett.model.Placement;
import org.cpsolver.coursett.model.TimeLocation;
import org.cpsolver.ifs.extension.Extension;
import org.cpsolver.ifs.solver.Solver;
import org.cpsolver.ifs.util.DataProperties;
import org.unitime.commons.hibernate.util.HibernateUtil;
import org.unitime.timetable.ApplicationProperties;
import org.unitime.timetable.model.Class_;
import org.unitime.timetable.model.Session;
import org.unitime.timetable.model.dao.Class_DAO;
import org.unitime.timetable.model.dao.SessionDAO;
import org.unitime.timetable.model.dao._RootDAO;
import org.unitime.timetable.util.Constants;


/**
 * @author Tomas Muller
 */
public class MuniPdFKSCZVDatePatterns extends Extension<Lecture, Placement> {
	private static Log sLog = LogFactory.getLog(MuniPdFKSCZVDatePatterns.class);
    private Hashtable<Integer, List<DatePattern>> iDatePatternsExt = new Hashtable<Integer, List<DatePattern>>();
    private Hashtable<Integer, List<DatePattern>> iDatePatternsAll = new Hashtable<Integer, List<DatePattern>>();

    
    public MuniPdFKSCZVDatePatterns(Solver<Lecture, Placement> solver, DataProperties properties) {
        super(solver, properties);
        org.hibernate.Session hibSession = SessionDAO.getInstance().createNewSession();
        try {
            for (org.unitime.timetable.model.DatePattern dp: (List<org.unitime.timetable.model.DatePattern>)hibSession.createQuery(
            		"from DatePattern dp where dp.session.uniqueId = :sessionId and dp.type = :type and dp.name like :name order by dp.offset desc")
            		.setLong("sessionId", properties.getPropertyLong("General.SessionId", -1))
            		.setInteger("type", org.unitime.timetable.model.DatePattern.sTypeExtended)
            		.setString("name", "T%den %")
            		.list()) {
            	BitSet weekCode = dp.getPatternBitSet();
            	int nrWeeks = weekCode.cardinality() / 7;
            	List<DatePattern> patterns = iDatePatternsExt.get(nrWeeks);
            	if (patterns == null) {
            		patterns = new ArrayList<DatePattern>();
            		iDatePatternsExt.put(nrWeeks, patterns);
            	}
            	patterns.add(new DatePattern(dp.getUniqueId(), dp.getName(), weekCode));
            }
            for (org.unitime.timetable.model.DatePattern dp: (List<org.unitime.timetable.model.DatePattern>)hibSession.createQuery(
            		"from DatePattern dp where dp.session.uniqueId = :sessionId and dp.name like :name order by dp.offset desc")
            		.setLong("sessionId", properties.getPropertyLong("General.SessionId", -1))
            		.setString("name", "T%den %")
            		.list()) {
            	BitSet weekCode = dp.getPatternBitSet();
            	int nrWeeks = weekCode.cardinality() / 7;
            	List<DatePattern> patterns = iDatePatternsAll.get(nrWeeks);
            	if (patterns == null) {
            		patterns = new ArrayList<DatePattern>();
            		iDatePatternsAll.put(nrWeeks, patterns);
            	}
            	patterns.add(new DatePattern(dp.getUniqueId(), dp.getName(), weekCode));
            }
        } finally {
        	hibSession.close();
        }
    }
    
    private Class_ parent(Class_ clazz) {
    	Class_ parent = (clazz == null ? null : clazz.getParentClass());
    	if (parent != null && 
    		parent.getSchedulingSubpart().getItype().equals(clazz.getSchedulingSubpart().getItype()) &&
    		clazz.effectiveDatePattern().equals(parent.effectiveDatePattern()))
    		return parent;
    	return null;
    }
    
    private Class_ child(Class_ clazz) {
    	if (clazz == null) return null;
    	for (Class_ child: clazz.getChildClasses()) {
    		if (child.getSchedulingSubpart().getItype().equals(clazz.getSchedulingSubpart().getItype()) && child.effectiveDatePattern().equals(clazz.effectiveDatePattern()))
    			return child;
    	}
    	return null;
    }
    
    @Override
    public void variableAdded(Lecture lecture) {
        if (lecture.timeLocations().isEmpty()) return;
        List<TimeLocation> times = new ArrayList<TimeLocation>(lecture.timeLocations());
        
    	// SP courses take all Týden % date patterns (other take just the extended ones)
    	// boolean sp = lecture.getName().startsWith("SP ");
    	// SP courses have Thursday
        boolean sp = false;
        for  (TimeLocation t: times)
        	if ((t.getDayCode() & Constants.DAY_CODES[Constants.DAY_THU]) != 0) {
        		sp = true; break;
        	}
        
        if (times.get(0).getDatePatternName().matches("[1-6]x")) {
        	Class_ clazz = Class_DAO.getInstance().get(lecture.getClassId());
            int parents = 0;
            Class_ parent = parent(clazz);
            while (parent != null) {
            	parents++;
            	parent = parent(parent);
            }
            int children = 0;
            Class_ child = child(clazz);
            while (child != null) {
            	children++;
            	child = child(child);
            }	
        	
        	int n = Integer.parseInt(times.get(0).getDatePatternName().substring(0, 1));
            lecture.timeLocations().clear();
            
            for  (TimeLocation t: times) {
            	List<DatePattern> datePatterns = (sp ? iDatePatternsAll : iDatePatternsExt).get(n);
            	for (int i = parents; i < datePatterns.size() - children; i++) {
            		DatePattern dp = datePatterns.get(i);
            		
                	// Only Týden 0 allows for Thursday
                	if (!dp.getName().endsWith("den 0") && (t.getDayCode() & Constants.DAY_CODES[Constants.DAY_THU]) != 0)
                		continue;

                	// Clone time location with the new date pattern
                	TimeLocation time = new TimeLocation(t.getDayCode(), t.getStartSlot(), t.getLength(),
                            t.getPreference(), t.getNormalizedPreference(),
                            dp.getId(), dp.getName(), dp.getPattern(),
                            t.getBreakTime());
                    time.setTimePatternId(t.getTimePatternId());
                    lecture.timeLocations().add(time);
                }
            }
        }
        lecture.clearValueCache();
    }
    
    
    static String[] sCombinations = new String[] {
        // 1x
        "1,0,0,0,0,0,0,0,0,0,0,0,0",
        "0,1,0,0,0,0,0,0,0,0,0,0,0",
        "0,0,1,0,0,0,0,0,0,0,0,0,0",
        "0,0,0,1,0,0,0,0,0,0,0,0,0",
        "0,0,0,0,1,0,0,0,0,0,0,0,0",
        "0,0,0,0,0,1,0,0,0,0,0,0,0",
        "0,0,0,0,0,0,1,0,0,0,0,0,0",
        "0,0,0,0,0,0,0,1,0,0,0,0,0",
        "0,0,0,0,0,0,0,0,1,0,0,0,0",
        "0,0,0,0,0,0,0,0,0,1,0,0,0",
        "0,0,0,0,0,0,0,0,0,0,1,0,0",
        "0,0,0,0,0,0,0,0,0,0,0,1,0",
        "0,0,0,0,0,0,0,0,0,0,0,0,1",
        // 2x
        "1,1,0,0,0,0,0,0,0,0,0,0,0",
        "0,1,1,0,0,0,0,0,0,0,0,0,0",
        "0,0,1,1,0,0,0,0,0,0,0,0,0",
        "0,0,0,1,1,0,0,0,0,0,0,0,0",
        "0,0,0,0,1,1,0,0,0,0,0,0,0",
        "0,0,0,0,0,1,1,0,0,0,0,0,0",
        "0,0,0,0,0,0,1,1,0,0,0,0,0",
        "0,0,0,0,0,0,0,1,1,0,0,0,0",
        "0,0,0,0,0,0,0,0,1,1,0,0,0",
        "0,0,0,0,0,0,0,0,0,1,1,0,0",
        "0,0,0,0,0,0,0,0,0,0,1,1,0",
        "0,0,0,0,0,0,0,0,0,0,0,1,1",
        "1,0,0,0,0,0,1,0,0,0,0,0,0",
        "0,1,0,0,0,0,0,1,0,0,0,0,0",
        "0,0,1,0,0,0,0,0,1,0,0,0,0",
        "0,0,0,1,0,0,0,0,0,1,0,0,0",
        "0,0,0,0,1,0,0,0,0,0,1,0,0",
        "0,0,0,0,0,1,0,0,0,0,0,1,0",
        "0,0,0,0,0,0,1,0,0,0,0,0,1",
        // 3x
        "1,1,1,0,0,0,0,0,0,0,0,0,0",
        "0,1,1,1,0,0,0,0,0,0,0,0,0",
        "0,0,1,1,1,0,0,0,0,0,0,0,0",
        "0,0,0,1,1,1,0,0,0,0,0,0,0",
        "0,0,0,0,1,1,1,0,0,0,0,0,0",
        "0,0,0,0,0,1,1,1,0,0,0,0,0",
        "0,0,0,0,0,0,1,1,1,0,0,0,0",
        "0,0,0,0,0,0,0,1,1,1,0,0,0",
        "0,0,0,0,0,0,0,0,1,1,1,0,0",
        "0,0,0,0,0,0,0,0,0,1,1,1,0",
        "0,0,0,0,0,0,0,0,0,0,1,1,1",
        "1,0,0,0,1,0,0,0,1,0,0,0,0",
        "0,1,0,0,0,1,0,0,0,1,0,0,0",
        "0,0,1,0,0,0,1,0,0,0,1,0,0",
        "0,0,0,1,0,0,0,1,0,0,0,1,0",
        "0,0,0,0,1,0,0,0,1,0,0,0,1",
        // 4x
        "1,1,1,1,0,0,0,0,0,0,0,0,0",
        "0,1,1,1,1,0,0,0,0,0,0,0,0",
        "0,0,1,1,1,1,0,0,0,0,0,0,0",
        "0,0,0,1,1,1,1,0,0,0,0,0,0",
        "0,0,0,0,1,1,1,1,0,0,0,0,0",
        "0,0,0,0,0,1,1,1,1,0,0,0,0",
        "0,0,0,0,0,0,1,1,1,1,0,0,0",
        "0,0,0,0,0,0,0,1,1,1,1,0,0",
        "0,0,0,0,0,0,0,0,1,1,1,1,0",
        "0,0,0,0,0,0,0,0,0,1,1,1,1",
        "1,0,0,1,0,0,1,0,0,1,0,0,0",
        "0,1,0,0,1,0,0,1,0,0,1,0,0",
        "0,0,1,0,0,1,0,0,1,0,0,1,0",
        "0,0,0,1,0,0,1,0,0,1,0,0,1",
        // 5x
        "1,1,1,1,1,0,0,0,0,0,0,0,0",
        "0,1,1,1,1,1,0,0,0,0,0,0,0",
        "0,0,1,1,1,1,1,0,0,0,0,0,0",
        "0,0,0,1,1,1,1,1,0,0,0,0,0",
        "0,0,0,0,1,1,1,1,1,0,0,0,0",
        "0,0,0,0,0,1,1,1,1,1,0,0,0",
        "0,0,0,0,0,0,1,1,1,1,1,0,0",
        "0,0,0,0,0,0,0,1,1,1,1,1,0",
        "0,0,0,0,0,0,0,0,1,1,1,1,1",
        "1,0,1,0,1,0,1,0,1,0,0,0,0",
        "0,1,0,1,0,1,0,1,0,1,0,0,0",
        "0,0,1,0,1,0,1,0,1,0,1,0,0",
        "0,0,0,1,0,1,0,1,0,1,0,1,0",
        "0,0,0,0,1,0,1,0,1,0,1,0,1",
        // 6x
        "1,1,1,1,1,1,0,0,0,0,0,0,0",
        "0,1,1,1,1,1,1,0,0,0,0,0,0",
        "0,0,1,1,1,1,1,1,0,0,0,0,0",
        "0,0,0,1,1,1,1,1,1,0,0,0,0",
        "0,0,0,0,1,1,1,1,1,1,0,0,0",
        "0,0,0,0,0,1,1,1,1,1,1,0,0",
        "0,0,0,0,0,0,1,1,1,1,1,1,0",
        "0,0,0,0,0,0,0,1,1,1,1,1,1",
        "1,0,1,0,1,0,1,0,1,0,1,0,0",
        "0,1,0,1,0,1,0,1,0,1,0,1,0",
        "0,0,1,0,1,0,1,0,1,0,1,0,1",
    };

    public static void main(String[] args) {
        try {
            HibernateUtil.configureHibernate(ApplicationProperties.getProperties());

            org.hibernate.Session hibSession = new _RootDAO().getSession();
            
			Session session = Session.getSessionUsingInitiativeYearTerm(
                    ApplicationProperties.getProperty("initiative", "PdF"),
                    ApplicationProperties.getProperty("year","2011"),
                    ApplicationProperties.getProperty("term","Podzim")
                    );
            
            if (session==null) {
                sLog.error("Academic session not found, use properties initiative, year, and term to set academic session.");
                System.exit(0);
            } else {
                sLog.info("Session: "+session);
            }
            
            List<BitSet> weeks = new ArrayList<BitSet>();
            BitSet fullTerm = session.getDefaultDatePattern().getPatternBitSet();
            int cnt = 0;
            for (int i = 0; i < fullTerm.length(); i++) {
                if (fullTerm.get(i)) {
                    int w = (cnt++) / 7;
                    if (weeks.size() == w) {weeks.add(new BitSet(fullTerm.length())); }
                    weeks.get(w).set(i);
                }
            }
            
            for (String c: sCombinations) {
                BitSet weekCode = new BitSet(weeks.get(0).length());
                String dp = "";
                int f = -1, i = 0;;
                for (String x: c.split(",")) {
                    if (x.equals("1")) {
                        if (f < 0) f = 1 + i;
                        weekCode.or(weeks.get(i));
                    } else {
                        if (f > 0) {
                            if (!dp.isEmpty()) dp += ",";
                            if (f == i) dp += "" + f;
                            else dp += f + "-" + i;
                            f = -1;
                        }
                    }
                    i++;
                }
                if (f > 0) {
                    if (!dp.isEmpty()) dp += ",";
                    if (f == weeks.size()) dp += "" + f;
                    else dp += f + "-" + weeks.size();
                }
                org.unitime.timetable.model.DatePattern p = org.unitime.timetable.model.DatePattern.findByName(session, "Týden " + dp);
                if (p == null) {
                	p = new org.unitime.timetable.model.DatePattern();
                	p.setSession(session);
                	p.setName("Týden " + dp);
                	p.setOffset(fullTerm.nextSetBit(0) - weekCode.nextSetBit(0));
                	p.setType(org.unitime.timetable.model.DatePattern.sTypeExtended);
                	p.setVisible(true);
                	String pattern = "";
                	for (int j = weekCode.nextSetBit(0); j < weekCode.length(); j++)
                		pattern += (weekCode.get(j) ? "1" : "0");
                	p.setPattern(pattern);
                	hibSession.saveOrUpdate(p);
                } else {
                	String pattern = "";
                	for (int j = weekCode.nextSetBit(0); j < weekCode.length(); j++)
                		pattern += (weekCode.get(j) ? "1" : "0");
                	p.setOffset(fullTerm.nextSetBit(0) - weekCode.nextSetBit(0));
                	p.setPattern(pattern);
                	p.setType(org.unitime.timetable.model.DatePattern.sTypeExtended);
                	p.setVisible(true);
                	hibSession.saveOrUpdate(p);
                }
            }

            hibSession.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
	}

}