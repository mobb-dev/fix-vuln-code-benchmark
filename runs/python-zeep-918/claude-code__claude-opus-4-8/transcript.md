**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: mvantellingen/python-zeep
2	Vulnerability type: Server-Side Request Forgery (CWE-918)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  src/zeep/exceptions.py
7	    - lines 114-116   in: def __init__(self, name, content):
8	
9	  src/zeep/loader.py
10	    - lines 5-22
11	    - lines 45-51     …(+690 more chars)
**Claude:** Let me read the relevant files to understand the vulnerability.

**→ Read**(file_path=/work/src/zeep/loader.py)
  ↳ *result:* 1	import os.path
2	import typing
3	from urllib.parse import urljoin, urlparse, urlunparse
4	
5	from lxml import etree
6	from lxml.etree import Resolver, XMLParser, XMLSyntaxError, fromstring
7	
8	from zeep.exceptions import DTDForbidden, EntitiesForbidden, XMLSyntaxError
9	from zeep.settings import Settings
10	
11	
12	class ImportResolver(Resolver)  …(+5540 more chars)
**→ Read**(file_path=/work/src/zeep/settings.py)
  ↳ *result:* 1	import threading
2	from contextlib import contextmanager
3	
4	import attr
5	
6	
7	@attr.s(slots=True)
8	class Settings:
9	    """
10	
11	    :param strict: boolean to indicate if the lxml should be parsed a 'strict'.
12	      If false then the recover mode is enabled which tries to parse invalid
13	      XML as best as it can.
14	    :type strict  …(+2848 more chars)
**→ Read**(file_path=/work/src/zeep/exceptions.py)
  ↳ *result:* 1	class Error(Exception):
2	    def __init__(self, message=""):
3	        super(Exception, self).__init__(message)
4	        self.message = message
5	
6	    def __repr__(self):
7	        return "%s(%r)" % (self.__class__.__name__, self.message)
8	
9	
10	class XMLSyntaxError(Error):
11	    def __init__(self, *args, **kwargs):
12	        self.content  …(+2926 more chars)
**→ Read**(file_path=/work/src/zeep/wsdl/wsdl.py, limit=160)
  ↳ *result:* 1	"""
2	zeep.wsdl.wsdl
3	~~~~~~~~~~~~~~
4	
5	"""
6	
7	import logging
8	import operator
9	import os
10	import typing
11	import warnings
12	from collections import OrderedDict
13	
14	from lxml import etree
15	
16	from zeep.exceptions import IncompleteMessage
17	from zeep.loader import absolute_location, is_relative_path, load_external
18	from zeep.se  …(+5163 more chars)
**→ Read**(file_path=/work/src/zeep/xsd/schema.py, offset=90, limit=90)
  ↳ *result:* 90	                    seen.add(element.qname)
91	
92	    @property
93	    def types(self):
94	        """Yield all global xsd.Type objects
95	
96	        :rtype: Iterable of zeep.xsd.ComplexType
97	
98	        """
99	        seen = set()
100	        for document in self.documents:
101	            for type_ in document._types.values():
102	          …(+3246 more chars)
**Claude:** The vulnerability is clear: `Settings` has a documented `forbid_external` option (default `True`) meant to block external resource access in DTDs/entities, but `ImportResolver` in `loader.py` never checks it — it unconditionally fetches any `http`/`https` URL referenced in parsed XML, enabling SSRF. Let me look at the tests and how the resolver/settings flow.

**→ Bash**(command=grep -rn "forbid_external\|ExternalReferenceForbidden\|ImportResolver" --include=*.py)
  ↳ *result:* src/zeep/settings.py:22:    :param forbid_external: disallow any access to remote or local resources
src/zeep/settings.py:23:      in external entities or DTD and raising an ExternalReferenceForbidden
src/zeep/settings.py:25:    :type forbid_external: bool
src/zeep/settings.py:54:    forbid_external = attr.ib(default=True)
src/zeep/loader.py:12:cla  …(+102 more chars)
**→ Bash**(command=grep -rn "resolve_entities\|no_network\|DTD\|external" tests/ --include=*.py | head -30)
  ↳ *result:* tests/test_loader.py:4:from zeep.exceptions import DTDForbidden, EntitiesForbidden
tests/test_loader.py:39:    # DTD is allowed by default in defusexml so we follow this behaviour
tests/test_loader.py:40:    with pytest.raises(DTDForbidden):
tests/utils.py:6:        remove_blank_text=True, remove_comments=True, resolve_entities=False
tests/test_wsd  …(+128 more chars)
**→ Read**(file_path=/work/tests/test_loader.py)
  ↳ *result:* 1	import pytest
2	
3	from tests.utils import DummyTransport
4	from zeep.exceptions import DTDForbidden, EntitiesForbidden
5	from zeep.loader import parse_xml
6	from zeep.settings import Settings
7	
8	
9	def test_huge_text():
10	    # libxml2>=2.7.3 has XML_MAX_TEXT_LENGTH 10000000 without XML_PARSE_HUGE
11	    settings = Settings(xml_huge_tree=True  …(+1199 more chars)
**Claude:** Now I understand the vulnerability fully. The `forbid_external` setting exists and is documented to raise `ExternalReferenceForbidden`, but neither the exception nor the enforcement exists. The `ImportResolver` blindly fetches any external URL. Let me implement the fix.

First, add the `ExternalReferenceForbidden` exception:

**→ Edit**(replace_all=false, file_path=/work/src/zeep/exceptions.py, old_string=class EntitiesForbidden(Error):
    def __init__(self, name, content):
        super().__init__()
        self.name = name
        self.cont  …(+147 more chars), new_string=class EntitiesForbidden(Error):
    def __init__(self, name, content):
        super().__init__()
        self.name = name
        self.cont  …(+638 more chars))
  ↳ *result:* The file /work/src/zeep/exceptions.py has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now enforce the setting in `ImportResolver` and pass settings through `parse_xml`:

**→ Edit**(replace_all=false, file_path=/work/src/zeep/loader.py, old_string=from zeep.exceptions import DTDForbidden, EntitiesForbidden, XMLSyntaxError
from zeep.settings import Settings


class ImportResolver(Resolv  …(+336 more chars), new_string=from zeep.exceptions import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    XMLSyntaxError,
)
from zeep.setti  …(+549 more chars))
  ↳ *result:* The file /work/src/zeep/loader.py has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/src/zeep/loader.py, old_string=    parser.resolvers.add(ImportResolver(transport)), new_string=    parser.resolvers.add(ImportResolver(transport, settings)))
  ↳ *result:* The file /work/src/zeep/loader.py has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Let me simplify the exception signature to match what's meaningfully available at the resolve call site:

**→ Edit**(replace_all=false, file_path=/work/src/zeep/exceptions.py, old_string=class ExternalReferenceForbidden(Error):
    def __init__(self, context, base_url, sysid, pubid):
        super().__init__()
        self.co  …(+348 more chars), new_string=class ExternalReferenceForbidden(Error):
    def __init__(self, sysid, pubid):
        super().__init__()
        self.sysid = sysid
         …(+168 more chars))
  ↳ *result:* The file /work/src/zeep/exceptions.py has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/src/zeep/loader.py, old_string=            if self.settings.forbid_external:
                raise ExternalReferenceForbidden(context, url, url, pubid), new_string=            if self.settings.forbid_external:
                raise ExternalReferenceForbidden(url, pubid))
  ↳ *result:* The file /work/src/zeep/loader.py has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now let me verify the existing tests still pass and the fix works:

**→ Bash**(command=python -m pytest tests/test_loader.py -q 2>&1 | tail -20)
  ↳ *result:* /usr/local/bin/python: No module named pytest
**→ Bash**(command=pip install -q pytest pytest-asyncio 2>&1 | tail -3; python -m pytest tests/test_loader.py tests/test_wsdl.py -q 2>&1 | tail -25)
  ↳ *result:* WARNING: Retrying (Retry(total=0, connect=None, read=None, redirect=None, status=None)) after connection broken by 'ProxyError('Cannot connect to proxy.', OSError('Tunnel connection failed: 403 blocked by egress allowlist'))': /simple/pytest/
ERROR: Could not find a version that satisfies the requirement pytest (from versions: none)
ERROR: No match  …(+79 more chars)
**Claude:** No network for pytest. Let me verify with a direct script:

**→ Bash**(command=python -c "
import sys; sys.path.insert(0, 'tests')
from zeep.loader import parse_xml
from zeep.settings import Settings
from zeep.exception  …(+933 more chars))
  ↳ *result:* Exit code 1
Traceback (most recent call last):
  File "<string>", line 3, in <module>
ModuleNotFoundError: No module named 'zeep'
**→ Bash**(command=python -c "
import sys; sys.path.insert(0, 'src')
from zeep.loader import parse_xml
from zeep.settings import Settings
from zeep.exceptions   …(+714 more chars))
  ↳ *result:* Exit code 1
Traceback (most recent call last):
  File "<string>", line 3, in <module>
  File "/work/src/zeep/__init__.py", line 1, in <module>
    from zeep.client import AsyncClient, CachingClient, Client
  File "/work/src/zeep/client.py", line 5, in <module>
    from zeep.settings import Settings
  File "/work/src/zeep/settings.py", line 4, in <m  …(+66 more chars)
**→ Bash**(command=python -c "import zeep; print(zeep.__file__)" 2>&1; pip show zeep 2>/dev/null | grep -i location; python -c "import attr" 2>&1 && echo "attr  …(+4 more chars))
  ↳ *result:* Exit code 1
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'zeep'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'attr'
**→ Bash**(command=find / -name "attr" -type d 2>/dev/null | head; echo "---venvs---"; ls /work 2>/dev/null; find / -path "*/site-packages/lxml" -maxdepth 8 -t  …(+24 more chars))
  ↳ *result:* /proc/1/attr
/proc/101/attr
/proc/103/attr
/proc/104/attr
/proc/105/attr
/proc/1/task/1/attr
/proc/1/task/7/attr
/proc/1/task/8/attr
/proc/101/task/101/attr
/proc/104/task/104/attr
---venvs---
CHANGES
CONTRIBUTORS.rst
FINDING.txt
LICENSE
MANIFEST.in
Makefile
README.md
SECURITY.md
benchmark
codecov.yml
docs
examples
mypy.ini
pyproject.toml
src
tests  …(+8 more chars)
**Claude:** Dependencies (`attr`, `lxml`) aren't installed and there's no network. Let me at least verify the modules compile and test the resolver logic in isolation with stubs:

**→ Bash**(command=python -m py_compile src/zeep/loader.py src/zeep/exceptions.py src/zeep/settings.py && echo "compile OK")
  ↳ *result:* compile OK
**→ Bash**(command=python -c "
import sys, types
# stub lxml.etree.Resolver so we can unit-test ImportResolver logic without lxml installed
lxml = types.Module  …(+2078 more chars))
  ↳ *result:* PASS blocked, transport.load calls= [] -> ExternalReferenceForbidden(system_id='http://evil/x.dtd', public_id=None)
PASS allowed when opted-out, transport.load calls= ['http://ok/x.dtd'] result= ('RESOLVED', b'<x/>')
PASS non-http returns None calls= []
**Claude:** The fix works correctly. Let me verify there are no other `ImportResolver(` instantiations anywhere that would break with the new required argument:

**→ Bash**(command=grep -rn "ImportResolver(" --include=*.py .)
  ↳ *result:* src/zeep/loader.py:17:class ImportResolver(Resolver):
src/zeep/loader.py:56:    parser.resolvers.add(ImportResolver(transport, settings))
**Claude:** All data flows (`wsdl.py:_get_xml_document`, `schema.py:add_document_by_url`) already pass `settings` into `load_external` → `parse_xml`, so the `forbid_external` setting now propagates to the resolver everywhere. Let me do a final review of the changed loader code:

**→ Read**(file_path=/work/src/zeep/loader.py, offset=1, limit=30)
  ↳ *result:* 1	import os.path
2	import typing
3	from urllib.parse import urljoin, urlparse, urlunparse
4	
5	from lxml import etree
6	from lxml.etree import Resolver, XMLParser, XMLSyntaxError, fromstring
7	
8	from zeep.exceptions import (
9	    DTDForbidden,
10	    EntitiesForbidden,
11	    ExternalReferenceForbidden,
12	    XMLSyntaxError,
13	)
14	from zeep.se  …(+587 more chars)
**Claude:** The remediation is complete. Here's a summary of what I did.

## Vulnerability

**Server-Side Request Forgery (CWE-918)** in `python-zeep`'s XML loader.

`zeep.settings.Settings` defines `forbid_external` (default `True`), documented as: *"disallow any access to remote or local resources in external entities or DTD and raising an `ExternalReferenceForbidden` exception."* However:

1. The `ExternalReferenceForbidden` exception **did not exist**.
2. The setting was **never enforced**. `ImportResolver.resolve()` in `src/zeep/loader.py` unconditionally fetched any `http`/`https` URL referenced from parsed XML (e.g. an external DTD/entity `SYSTEM` reference) via `transport.load()`.

So when zeep parsed attacker-influenced XML (a WSDL/XSD/SOAP response), an external reference could coerce the application into issuing HTTP(S) requests to arbitrary internal/external hosts — classic SSRF — despite the secure-by-default setting promising to prevent exactly that.

## Fix (behavior-preserving)

- **`src/zeep/exceptions.py`** — added the `ExternalReferenceForbidden` exception class (mirroring the existing `DTDForbidden`/`EntitiesForbidden` pattern).
- **`src/zeep/loader.py`** — `ImportResolver` now receives `settings` and, when `forbid_external` is set, raises `ExternalReferenceForbidden` instead of fetching the external URL. `parse_xml` passes `settings` into the resolver.

Because `parse_xml` always resolves to a `Settings` instance (default `forbid_external=True`), the protection applies by default across every entry point (`wsdl.py`, `schema.py`, etc., which already thread `settings` through `load_external`).

Behavior is unchanged for legitimate use:
- Benign XML parses exactly as before.
- Non-`http(s)` schemes are untouched.
- Setting `forbid_external=False` restores the original opt-in behavior of loading external references via the transport.

I verified the modules compile and unit-tested the resolver logic in isolation (lxml/attr aren't installed and there's no network here): blocked-by-default raises without ever calling `transport.load`, opt-out still loads, and non-http references are passed through.


---
**Final (success):** The remediation is complete. Here's a summary of what I did.

## Vulnerability

**Server-Side Request Forgery (CWE-918)** in `python-zeep`'s XML loader.

`zeep.settings.Settings` defines `forbid_external` (default `True`), documented as: *"disallow any access to remote or local resources in external entities or DTD and raising an `ExternalReferenceForbidden` exception."* However:

1. The `ExternalReferenceForbidden` exception **did not exist**.
2. The setting was **never enforced**. `ImportResolver.resolve()` in `src/zeep/loader.py` unconditionally fetched any `http`/`https` URL referenced from parsed XML (e.g. an external DTD/entity `SYSTEM` reference) via `transport.load()`.

So when zeep parsed attacker-influenced XML (a WSDL/XSD/SOAP response), an external reference could coerce the application into issuing HTTP(S) requests to arbitrary internal/external hosts — classic SSRF — despite the secure-by-default setting promising to prevent exactly that.

## Fix (behavior-preserving)

- **`src/zeep/exceptions.py`** — added the `ExternalReferenceForbidden` exception class (mirroring the existing `DTDForbidden`/`EntitiesForbidden` pattern).
- **`src/zeep/loader.py`** — `ImportResolver` now receives `settings` and, when `forbid_external` is set, raises `ExternalReferenceForbidden` instead of fetching the external URL. `parse_xml` passes `settings` into the resolver.

Because `parse_xml` always resolves to a `Settings` instance (default `forbid_external=True`), the protection applies by default across every entry point (`wsdl.py`, `schema.py`, etc., which already thread `settings` through `load_external`).

Behavior is unchanged for legitimate use:
- Benign XML parses exactly as before.
- Non-`http(s)` schemes are untouched.
- Setting `forbid_external=False` restores the original opt-in behavior of loading external references via the transport.

I verified the modules compile and unit-tested the resolver logic in isolation (lxml/attr aren't installed and there's no network here): blocked-by-default raises without ever calling `transport.load`, opt-out still loads, and non-http references are passed through.

*turns 25 · cost $0.883*
