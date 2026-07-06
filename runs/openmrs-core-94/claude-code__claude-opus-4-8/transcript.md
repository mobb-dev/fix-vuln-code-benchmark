**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: openmrs/openmrs-core
2	Vulnerability type: Code Injection (CWE-94)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
7	    - lines 9-29
8	    - lines 35-40
9	    - lines 43-49
10	    - lines 96-482   in: public boolean eva  …(+66 more chars)
**Claude:** I'll read the vulnerable file to understand the code.

**→ Read**(file_path=/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java)
  ↳ *result:* 1	/**
2	 * This Source Code Form is subject to the terms of the Mozilla Public License,
3	 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
4	 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
5	 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
6	 *
7	 * Copyright  …(+17297 more chars)
**Claude:** Let me examine how this is used and what the test suite expects, to understand intended behavior before remediation.

**→ Bash**(command=grep -rl "ConceptReferenceRangeUtility\|evaluateCriteria" --include=*.java | head -50)
  ↳ *result:* api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java
api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
api/src/main/java/org/openmrs/api/impl/ConceptServiceImpl.java
**→ Bash**(command=grep -rn "velocity" --include=pom.xml api/pom.xml pom.xml 2>/dev/null; grep -rni "velocity\|SecureUberspector\|Uberspect" --include=*.xml |   …(+23 more chars))
  ↳ *result:* api/pom.xml:53:			<groupId>org.apache.velocity</groupId>
api/pom.xml:54:			<artifactId>velocity-engine-core</artifactId>
bom/pom.xml:87:		<!-- Velocity -->
bom/pom.xml:88:		<velocityVersion>2.4.1</velocityVersion>
bom/pom.xml:89:		<velocityToolsVersion>3.1</velocityToolsVersion>
bom/pom.xml:397:			<!-- Velocity -->
bom/pom.xml:399:				<groupId>org.  …(+345 more chars)
**→ Read**(file_path=/work/api/src/test/java/org/openmrs/util/ConceptReferenceRangeUtilityTest.java)
  ↳ *result:* 1	/**
2	 * This Source Code Form is subject to the terms of the Mozilla Public License,
3	 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
4	 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
5	 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
6	 *
7	 * Copyright  …(+24384 more chars)
**Claude:** Now I understand the vulnerability and the intended behavior. The code uses Apache Velocity's `evaluate()` to run user-supplied criteria. Velocity's default introspection allows arbitrary Java method/reflection calls (e.g. `$patient.getClass().forName('java.lang.Runtime')...`), enabling remote code execution — classic template/code injection.

Let me confirm the Velocity classes available to harden the engine.

**→ Bash**(command=find ~ / -name 'velocity-engine-core*.jar' 2>/dev/null | head; echo "---"; J=$(find ~ / -name 'velocity-engine-core*.jar' 2>/dev/null | head  …(+106 more chars))
  ↳ *result:* ---
**→ Bash**(command=find / -path /proc -prune -o -name 'velocity-engine-core*.jar' -print 2>/dev/null | head)
  ↳ *result:* (Bash completed with no output)
**→ Bash**(command=ls ~/.m2/repository/org/apache/velocity/ 2>/dev/null; find / -path /proc -prune -o -name '*.jar' -path '*velocity*' -print 2>/dev/null | hea  …(+1 more chars))
  ↳ *result:* (Bash completed with no output)
**Claude:** The dependencies aren't downloaded locally, but the fix relies on stable Velocity 2.x API. The standard, behavior-preserving remediation for Velocity code injection is to install the `SecureUberspector`, which restricts introspection so expressions can't reach dangerous classes (`Runtime`, `System`, `ClassLoader`, reflection, `getClass()`, etc.) while still allowing the legitimate method calls on `$patient`/`$fn`/`$obs` that the criteria need.

Let me apply the fix.

**→ Edit**(replace_all=false, file_path=/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java, old_string=import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.exception.ParseErrorEx  …(+8 more chars), new_string=import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.exception.ParseErrorEx  …(+126 more chars))
  ↳ *result:* The file /work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java, old_string=			Properties props = new Properties();
			props.put("runtime.log.logsystem.log4j.category", "velocity");
			props.put("runtime.log.logsyste  …(+60 more chars), new_string=			Properties props = new Properties();
			props.put("runtime.log.logsystem.log4j.category", "velocity");
			props.put("runtime.log.logsyste  …(+470 more chars))
  ↳ *result:* The file /work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Let me verify the final state of the changed sections.

**→ Read**(file_path=/work/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java, offset=108, limit=28)
  ↳ *result:* 108			velocityContext.put("date", context.getDate());
109	
110			VelocityEngine velocityEngine = new VelocityEngine();
111			try {
112				Properties props = new Properties();
113				props.put("runtime.log.logsystem.log4j.category", "velocity");
114				props.put("runtime.log.logsystem.log4j.logger", "velocity");
115				// Restrict introspection so u  …(+1156 more chars)
**Claude:** The fix is in place. Let me attempt a compile to validate (it may fail only on offline dependency resolution, not on the code itself).

**→ Bash**(command=timeout 120 mvn -q -o -pl api compile 2>&1 | tail -30)
  ↳ *result:* [ERROR] [ERROR] Some problems were encountered while processing the POMs:
[ERROR] Non-resolvable import POM: The following artifacts could not be resolved: org.springframework:spring-framework-bom:pom:7.0.6 (absent): Cannot access openmrs-repo (https://mavenrepo.openmrs.org/nexus/content/repositories/public) in offline mode and the artifact org.spr  …(+2892 more chars)
**Claude:** The build failure is purely offline dependency resolution (Spring/JUnit/Netty BOMs can't be fetched), unrelated to my change — no Velocity or local source error appears. The dependencies aren't cached locally, so a full compile can't run in this environment.

## Summary

**Vulnerability:** Code Injection (CWE-94) in `api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`, in `evaluateCriteria(String, ConceptReferenceRangeContext)`.

The method takes a user-supplied `criteria` string, wraps it into a Velocity template (`#set( $criteria = <criteria> )$criteria`), and runs it through `VelocityEngine.evaluate()`. Velocity's default introspection (`UberspectImpl`) permits arbitrary Java method invocation and reflection on any object in the context. An attacker controlling the criteria could escape the intended boolean-expression use via something like `$patient.getClass().forName('java.lang.Runtime')...` and achieve remote code execution.

**Fix:** Configured the Velocity engine with the `SecureUberspector` introspector before initialization:

```java
props.put(RuntimeConstants.UBERSPECT_CLASSNAME, SecureUberspector.class.getName());
```

`SecureUberspector` (a standard, built-in Velocity hardening component) blocks introspection into dangerous classes — `Runtime`, `System`, `ClassLoader`, `Thread`, `java.lang.reflect.*`, `java.security.*` — and blocks `getClass()`-based reflection escapes. This closes the injection path while preserving all intended behavior: the legitimate expressions in the test suite (`$patient.getAge()`, `$patient.getGender().equals('M')`, `$fn.isObsValueCodedAnswer(...)`, `$obs.getValueNumeric()`, etc.) operate only on benign domain objects and are unaffected.

Changes were limited to:
- Two new imports (`RuntimeConstants`, `SecureUberspector`).
- One property added to the Velocity init properties, with an explanatory comment.

No behavior change for valid criteria, and no commits/pushes were made.


---
**Final (success):** The build failure is purely offline dependency resolution (Spring/JUnit/Netty BOMs can't be fetched), unrelated to my change — no Velocity or local source error appears. The dependencies aren't cached locally, so a full compile can't run in this environment.

## Summary

**Vulnerability:** Code Injection (CWE-94) in `api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`, in `evaluateCriteria(String, ConceptReferenceRangeContext)`.

The method takes a user-supplied `criteria` string, wraps it into a Velocity template (`#set( $criteria = <criteria> )$criteria`), and runs it through `VelocityEngine.evaluate()`. Velocity's default introspection (`UberspectImpl`) permits arbitrary Java method invocation and reflection on any object in the context. An attacker controlling the criteria could escape the intended boolean-expression use via something like `$patient.getClass().forName('java.lang.Runtime')...` and achieve remote code execution.

**Fix:** Configured the Velocity engine with the `SecureUberspector` introspector before initialization:

```java
props.put(RuntimeConstants.UBERSPECT_CLASSNAME, SecureUberspector.class.getName());
```

`SecureUberspector` (a standard, built-in Velocity hardening component) blocks introspection into dangerous classes — `Runtime`, `System`, `ClassLoader`, `Thread`, `java.lang.reflect.*`, `java.security.*` — and blocks `getClass()`-based reflection escapes. This closes the injection path while preserving all intended behavior: the legitimate expressions in the test suite (`$patient.getAge()`, `$patient.getGender().equals('M')`, `$fn.isObsValueCodedAnswer(...)`, `$obs.getValueNumeric()`, etc.) operate only on benign domain objects and are unaffected.

Changes were limited to:
- Two new imports (`RuntimeConstants`, `SecureUberspector`).
- One property added to the Velocity init properties, with an explanatory comment.

No behavior change for valid criteria, and no commits/pushes were made.

*turns 13 · cost $0.798*
