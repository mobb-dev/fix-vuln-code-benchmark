**Codex:** I’ll read the finding and inspect the referenced code paths first, then make the smallest source change that removes the vulnerability while preserving behavior.

**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g '"'!node_modules'"' -g '"'!vendor'"'"`
```
FINDING.txt

```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** The worktree is clean. I found the finding file at the project root and I’m opening it with the nearby project structure so I can tie the report to the actual implementation.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: openmrs/openmrs-core
Vulnerability type: Code Injection (CWE-94)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
    - lines 9-29
    - lines 35-40
    - lines 43-49
    - lines 96-482   in: public boolean evaluateCriteria(String criteria, ConceptReferenceRangeContext co

```
**→ shell:** `/bin/bash -lc "rg --files -g '"'!node_modules'"' -g '"'!vendor'"' -g '"'!dist'"' -g '"'!build'"' | sed -n '1,200p'"`
```
uery/jsTree/themes/apple/style.css
webapp/src/main/webapp/WEB-INF/view/scripts/jquery/jsTree/themes/apple/icons.png
webapp/src/main/webapp/WEB-INF/view/scripts/jquery/jsTree/themes/apple/dot_for_ie.gif
webapp/src/main/webapp/WEB-INF/view/scripts/jquery/jsTree/jquery.tree.min.js
webapp/src/main/webapp/WEB-INF/view/scripts/jquery/jsTree/plugins/jquery.tree.themeroller.js
webapp/src/main/webapp/WEB-INF/view/scripts/jquery/jsTree/plugins/jquery.tree.checkbox.js
api/src/main/java/liquibase/ext/sqlgen  …(+1918 more chars)
```
**Codex:** The report points at `ConceptReferenceRangeUtility`, specifically criteria evaluation. I’m checking the implementation and tests around that class so the patch can target the injection surface without changing the supported criteria language.

**→ shell:** `/bin/bash -lc "nl -ba api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java | sed -n '1,540p'"`
```
     1	/**
     2	 * This Source Code Form is subject to the terms of the Mozilla Public License,
     3	 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
     4	 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
     5	 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
     6	 *
     7	 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
     8	 * graphic logo is a trademark of OpenMR  …(+18697 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "ConceptReferenceRangeUtility|evaluateCriteria|reference range|criteria" api/src/test api/src/main/java | head -n 200'`
```
(criteria.getPatient() != null) {
api/src/main/java/org/openmrs/api/db/hibernate/HibernateMedicationDispenseDAO.java:60:			predicates.add(criteriaBuilder.equal(md.get("patient"), criteria.getPatient()));
api/src/main/java/org/openmrs/api/db/hibernate/HibernateMedicationDispenseDAO.java:62:		if (criteria.getEncounter() != null) {
api/src/main/java/org/openmrs/api/db/hibernate/HibernateMedicationDispenseDAO.java:63:			predicates.add(criteriaBuilder.equal(md.get("encounter"), criteria.getEncounter(  …(+2267 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"groovy|GroovyShell|ScriptEngine|BeanShell|MVEL|Janino|Jexl|Expression\" api/pom.xml pom.xml api/src/main/java api/src/test -g '*.xml' -g '*.java'"`
```
api/src/main/java/org/openmrs/api/db/hibernate/HibernatePersonDAO.java:20:import jakarta.persistence.criteria.Expression;
api/src/main/java/org/openmrs/api/db/hibernate/HibernatePersonDAO.java:549:			Expression<String> concatenatedFields = cb.concat(root.get("aIsToB"), cb.concat("/", root.get("bIsToA")));
api/src/main/java/org/openmrs/scheduler/jobrunr/JobRunrRecurringTaskDetails.java:49:	public String getScheduleExpression() {
api/src/main/java/org/openmrs/scheduler/jobrunr/JobRunrRecurringTask  …(+3833 more chars)
```
**Codex:** The injection comes from constructing a Velocity template directly from the criteria string. I’m looking at existing tests and data fixtures now to understand the exact criteria forms the application already relies on.

**→ shell:** `/bin/bash -lc "nl -ba api/src/main/java/org/openmrs/ConceptReferenceRangeContext.java | sed -n '1,180p'"`
```
     1	/**
     2	 * This Source Code Form is subject to the terms of the Mozilla Public License,
     3	 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
     4	 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
     5	 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
     6	 *
     7	 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
     8	 * graphic logo is a trademark of OpenMR  …(+4299 more chars)
```
**→ shell:** `/bin/bash -lc "find api/src/test -name '*Concept*Reference*Range*' -o -name '*ReferenceRange*' -o -name '*Concept*Range*'"`
```
api/src/test/resources/org/openmrs/api/include/ConceptServiceTest-conceptReferenceRange.xml
api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java

```
**→ shell:** `/bin/bash -lc "rg -n \"ConceptReferenceRangeUtility|evaluateCriteria|\\"'$patient|'"\\"'$fn|'"\\"'$context|'"\\"'$obs|'"\\"'$date|'"\\"'$encounter" api/src/test api/src/main/resources api/src/test/res  …(+73 more chars)`
```
api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java:43:class ConceptReferenceRangeUtilityTest extends BaseContextSensitiveTest {
api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java:49:	private ConceptReferenceRangeUtility conceptReferenceRangeUtility;
api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java:60:		conceptReferenceRangeUtility = new ConceptReferenceRangeUtility();
api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtili  …(+7368 more chars)
```
**Codex:** The supported criteria are Java-like boolean expressions using Velocity property/method access (`$patient`, `$fn`, `$obs`, etc.). The remediation needs to stop arbitrary Velocity directives while keeping those expressions, so I’m checking the test file in detail before editing.

**→ shell:** `/bin/bash -lc "nl -ba api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java | sed -n '1,680p'"`
```
     1	/**
     2	 * This Source Code Form is subject to the terms of the Mozilla Public License,
     3	 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
     4	 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
     5	 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
     6	 *
     7	 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
     8	 * graphic logo is a trademark of OpenMR  …(+26168 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba api/src/test/resources/org/openmrs/api/include/ConceptServiceTest-conceptReferenceRange.xml | sed -n '1,240p'"`
```
     1	<?xml version='1.0' encoding='UTF-8'?>
     2	<!--
     3	
     4	    This Source Code Form is subject to the terms of the Mozilla Public License,
     5	    v. 2.0. If a copy of the MPL was not distributed with this file, You can
     6	    obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
     7	    the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
     8	
     9	    Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and t  …(+1526 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "velocity|Velocity" api/src/main/java api/src/test/java'`
```
api/src/main/java/org/openmrs/api/context/Context.java:72:import org.openmrs.notification.mail.velocity.VelocityMessagePreparator;
api/src/main/java/org/openmrs/api/context/Context.java:661:		return new VelocityMessagePreparator();
api/src/main/java/org/openmrs/notification/mail/velocity/VelocityMessagePreparator.java:10:package org.openmrs.notification.mail.velocity;
api/src/main/java/org/openmrs/notification/mail/velocity/VelocityMessagePreparator.java:15:import org.apache.velocity.VelocityCon  …(+3767 more chars)
```
**Codex:** The current implementation exposes two risks: criteria can break out into Velocity directives, and Velocity method introspection can reach reflective APIs. I’m checking the bundled Velocity version/config surface so the fix uses its sandbox support where available and adds input validation around the expression itself.

**→ shell:** `/bin/bash -lc "find ~/.m2/repository -path '*velocity*' -name '*.jar' | sed -n '1,80p'"`
**→ shell:** `/bin/bash -lc 'rg -n "velocity-engine|velocity|apache.velocity|version.velocity|velocity.version" pom.xml api/pom.xml */pom.xml'`
```
api/pom.xml:53:			<groupId>org.apache.velocity</groupId>
api/pom.xml:54:			<artifactId>velocity-engine-core</artifactId>
api/pom.xml:53:			<groupId>org.apache.velocity</groupId>
api/pom.xml:54:			<artifactId>velocity-engine-core</artifactId>
bom/pom.xml:88:		<velocityVersion>2.4.1</velocityVersion>
bom/pom.xml:89:		<velocityToolsVersion>3.1</velocityToolsVersion>
bom/pom.xml:399:				<groupId>org.apache.velocity</groupId>
bom/pom.xml:400:				<artifactId>velocity-engine-core</artifactId>
bom/pom.x  …(+376 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"SecureUberspector|uberspect|introspector.restrict|runtime.introspector\" ~/.m2/repository/org/apache/velocity ~/.m2/repository -g '*.properties' -g '*.java' -g '*.txt' 2>/dev/nu  …(+17 more chars)`
**→ shell:** `/bin/bash -lc 'rg -n "<maven.compiler|<java.version|<source>|<target>|maven-compiler" pom.xml api/pom.xml bom/pom.xml'`
```
pom.xml:111:					<artifactId>maven-compiler-plugin</artifactId>
pom.xml:801:		<maven.compiler.release>21</maven.compiler.release>

```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' api/pom.xml"`
```
<!--

    This Source Code Form is subject to the terms of the Mozilla Public License,
    v. 2.0. If a copy of the MPL was not distributed with this file, You can
    obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
    the terms of the Healthcare Disclaimer located at http://openmrs.org/license.

    Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
    graphic logo is a trademark of OpenMRS Inc.

-->
<project xmlns="http://maven.apache.or  …(+3230 more chars)
```
**Codex:** I’m going to add an expression validator in front of Velocity, configure Velocity’s secure introspector, and add regression tests that prove directives/reflection-style method access are rejected while the existing expression behavior remains intact.

**✎ files:** update `/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

**✎ files:** update `/work/api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java`

**Codex:** The code now rejects non-expression Velocity syntax and unsafe method access before evaluation, and Velocity is initialized with the secure uberspector. I’ve added focused regression tests and am running the utility test class to catch compatibility issues.

**→ shell:** `/bin/bash -lc './mvnw -pl api -Dtest=ConceptReferenceRangeUtilityTest test'`
```
wget: Failed to fetch https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.tar.gz

```
**Codex:** The Maven wrapper could not download Maven from Maven Central in this environment. I’m checking for a system Maven and then I’ll run the same focused test command with that if available.

**→ shell:** `/bin/bash -lc 'command -v mvn || true'`
```
/usr/bin/mvn

```
**→ shell:** `/bin/bash -lc 'java -version'`
```
openjdk version "21.0.11" 2026-04-21 LTS
OpenJDK Runtime Environment Temurin-21.0.11+10 (build 21.0.11+10-LTS)
OpenJDK 64-Bit Server VM Temurin-21.0.11+10 (build 21.0.11+10-LTS, mixed mode, sharing)

```
**→ shell:** `/bin/bash -lc 'git diff -- api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java'`
```
diff --git a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java b/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
index 6ece9de..fd79835 100644
--- a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
+++ b/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
@@ -19,6 +19,9 @@ import java.util.Date;
 import java.util.List;
 import java.util.Locale;
 import java.util.Properties;
+import java.util.Set;
+import java.util.regex  …(+7357 more chars)
```
**Codex:** A system Maven is available, so I’ll use that. I also spotted a formatting issue in the diff around the Velocity initialization block and will clean that up before the next test run.

**✎ files:** update `/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

**Codex:** The formatting issue is fixed. I’m running the focused Maven test with the installed Maven now.

**→ shell:** `/bin/bash -lc 'mvn -pl api -Dtest=ConceptReferenceRangeUtilityTest test'`
```
[INFO] Scanning for projects...
Downloading from openmrs-repo: https://mavenrepo.openmrs.org/nexus/content/repositories/public/org/springframework/spring-framework-bom/7.0.6/spring-framework-bom-7.0.6.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/springframework/spring-framework-bom/7.0.6/spring-framework-bom-7.0.6.pom
Downloading from openmrs-repo: https://mavenrepo.openmrs.org/nexus/content/repositories/public/org/junit/junit-bom/6.0.3/junit-bom-6.0.3.pom
Downloading f  …(+3669 more chars)
```
**Codex:** The focused test run is blocked by dependency resolution: Maven cannot resolve several BOMs because `mavenrepo.openmrs.org` is not reachable from this environment. I’m still doing a local sanity pass on the patch and tightening a couple of details that don’t require dependency downloads.

**✎ files:** update `/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

**→ shell:** `/bin/bash -lc "nl -ba api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java | sed -n '108,160p'"`
```
   108	
   109			assertTrue(conceptReferenceRangeUtility
   110			        .evaluateCriteria("$patient.getAgeInMonths() > 1 && $patient.getAgeInMonths() < 12", obs));
   111		}
   112	
   113		@Test
   114		public void testAgeInRange_shouldThrowExceptionIfCriteriaIsInvalid() {
   115			calendar = Calendar.getInstance();
   116			calendar.add(Calendar.YEAR, -1);
   117			person.setBirthdate(calendar.getTime());
   118	
   119			Obs obs = buildObs();
   120			obs.setPerson(person);
   121		
   122	  …(+1589 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java | sed -n '1,240p'"`
```
     1	/**
     2	 * This Source Code Form is subject to the terms of the Mozilla Public License,
     3	 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
     4	 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
     5	 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
     6	 *
     7	 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
     8	 * graphic logo is a trademark of OpenMR  …(+10419 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check'`
```
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:48: trailing whitespace.
+	
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:50: trailing whitespace.
+	
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:52: trailing whitespace.
+	
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:54: trailing whitespace.
+	
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:56: trailing whitespace.
+	
api/src/main/ja  …(+1987 more chars)
```
**Codex:** `git diff --check` caught trailing whitespace from the edit. I’m cleaning that mechanically and then I’ll rerun the local checks.

**→ shell:** `/bin/bash -lc "perl -0pi -e 's/[ \\t]+"'$//mg'"' api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java"`
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc "git diff --stat && git diff -- api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java | sed -n '1,  …(+6 more chars)`
```
 .../openmrs/util/ConceptReferenceRangeUtility.java | 96 +++++++++++++++++++++-
 .../util/ConceptReferenceRangeUtilityTest.java     | 26 ++++++
 2 files changed, 121 insertions(+), 1 deletion(-)
diff --git a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java b/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
index 6ece9de..9f9e387 100644
--- a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
+++ b/api/src/main/java/org/openmrs/util/Concep  …(+7231 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
 M api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java

```
**→ shell:** `/bin/bash -lc "awk 'length("'$0) > 110 { print FILENAME ":" FNR ":" length($0) ":" $0 }'"' api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java api/src/test/java/org/openmrs/util/Conce  …(+33 more chars)`
```
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:55:118:	private static final Set<String> ALLOWED_REFERENCES = Set.of("patient", "fn", "context", "obs", "encounter", "date");
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:59:115:	    "getDeclaredConstructors", "getDeclaredMethod", "getDeclaredMethods", "getMethod", "getMethods", "getRuntime",
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:140:115:			velocityEngine.evaluate(velocityC  …(+7707 more chars)
```
**→ shell:** `/bin/bash -lc 'mvn -o -pl api -Dtest=ConceptReferenceRangeUtilityTest test'`
```
[INFO] Scanning for projects...
[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[ERROR] Non-resolvable import POM: The following artifacts could not be resolved: org.springframework:spring-framework-bom:pom:7.0.6 (absent): Cannot access openmrs-repo (https://mavenrepo.openmrs.org/nexus/content/repositories/public) in offline mode and the artifact org.springframework:spring-framework-bom:pom:7.0.6 has not been downloaded from it before. @ org.openmrs:openmrs-bom:3.0.0-SN  …(+2775 more chars)
```
**Codex:** Offline Maven also fails because the required BOMs are not cached locally. One more local hardening pass found that Velocity’s quiet-reference syntax (`$!foo`) should be rejected too, so I’m adding explicit reference-token validation before wrapping up.

**✎ files:** update `/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

**Codex:** I’m adding a small regression case for quiet references as well, then I’ll run the non-network checks again.

**✎ files:** update `/work/api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java`

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc "git diff -- api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java | sed -n '1,320p'"`
```
diff --git a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java b/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
index 6ece9de..7cee650 100644
--- a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
+++ b/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
@@ -19,6 +19,9 @@ import java.util.Date;
 import java.util.List;
 import java.util.Locale;
 import java.util.Properties;
+import java.util.Set;
+import java.util.regex  …(+7947 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
 M api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java

```
**Codex:** I’m loosening the validator slightly to avoid narrowing the criteria language more than necessary. It will still block directives, reflection/classloader/runtime paths, quiet references, and mutating method prefixes, while leaving ordinary predicate methods available.

**✎ files:** update `/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 .../openmrs/util/ConceptReferenceRangeUtility.java | 114 ++++++++++++++++++++-
 .../util/ConceptReferenceRangeUtilityTest.java     |  34 ++++++
 2 files changed, 147 insertions(+), 1 deletion(-)

```
**→ shell:** `/bin/bash -lc 'mvn -pl api -Dtest=ConceptReferenceRangeUtilityTest test'`
```
[INFO] Scanning for projects...
Downloading from openmrs-repo: https://mavenrepo.openmrs.org/nexus/content/repositories/public/org/springframework/spring-framework-bom/7.0.6/spring-framework-bom-7.0.6.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/springframework/spring-framework-bom/7.0.6/spring-framework-bom-7.0.6.pom
Downloading from openmrs-repo: https://mavenrepo.openmrs.org/nexus/content/repositories/public/org/junit/junit-bom/6.0.3/junit-bom-6.0.3.pom
Downloading f  …(+3669 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java | sed -n '48,230p'"`
```
    48	
    49		private final long NULL_DATE_RETURN_VALUE = -1;
    50	
    51		private static final Pattern REFERENCE_PATTERN = Pattern.compile("\\$([A-Za-z_][A-Za-z0-9_]*)([^$]*)");
    52	
    53		private static final Pattern MEMBER_PATTERN = Pattern.compile("\\.\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*(\\()?");
    54	
    55		private static final Set<String> ALLOWED_REFERENCES = Set.of("patient", "fn", "context", "obs", "encounter", "date");
    56	
    57		private static final Set<String> DISALLOWE  …(+8356 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java | sed -n '122,162p'"`
```
   122			assertThrows(APIException.class, () -> conceptReferenceRangeUtility.evaluateCriteria("invalidCriteria", obs));
   123		}
   124	
   125		@Test
   126		public void evaluateCriteria_shouldThrowExceptionIfCriteriaContainsVelocityDirective() {
   127			Obs obs = buildObs();
   128			obs.setPerson(person);
   129	
   130			assertThrows(APIException.class, () -> conceptReferenceRangeUtility.evaluateCriteria("#set($criteria = true)", obs));
   131		}
   132	
   133		@Test
   134		public void e  …(+1185 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
 M api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java

```
**Codex:** The patch is functionally scoped now. I’m doing a small readability wrap on the new long assertions/config lines; no behavioral change.

**✎ files:** update `/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

**✎ files:** update `/work/api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java`

**Codex:** I’m running the final non-network checks and one last Maven attempt so the verification status is explicit.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat && git status --short'`
```
 M api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
 M api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java

```
**→ shell:** `/bin/bash -lc 'mvn -pl api -Dtest=ConceptReferenceRangeUtilityTest test'`
```
[INFO] Scanning for projects...
Downloading from openmrs-repo: https://mavenrepo.openmrs.org/nexus/content/repositories/public/org/springframework/spring-framework-bom/7.0.6/spring-framework-bom-7.0.6.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/springframework/spring-framework-bom/7.0.6/spring-framework-bom-7.0.6.pom
Downloading from openmrs-repo: https://mavenrepo.openmrs.org/nexus/content/repositories/public/org/junit/junit-bom/6.0.3/junit-bom-6.0.3.pom
Downloading f  …(+3669 more chars)
```
**Codex:** Implemented the remediation in [ConceptReferenceRangeUtility.java](/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java:116).

What changed:
- Added pre-validation for criteria to reject Velocity directives, quiet references, unknown roots, unsafe reflection/runtime members, and mutating method prefixes.
- Configured Velocity with `SecureUberspector`.
- Preserved normal criteria expressions using `$patient`, `$fn`, `$context`, `$obs`, `$encounter`, and `$date`.
- Added regression tests in [ConceptReferenceRangeUtilityTest.java](/work/api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java:125) for directive injection, reflection access, quiet references, and mutating method calls.

Verification:
- `git diff --check` passes.
- `mvn -pl api -Dtest=ConceptReferenceRangeUtilityTest test` could not run because Maven cannot resolve BOM dependencies due DNS/network failure for `mavenrepo.openmrs.org`.


---
*tokens — input 1627142 (cached 1532288), output 11596, reasoning 4120*
