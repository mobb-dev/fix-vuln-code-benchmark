**Codex:** I’ll read the finding and inspect the affected code paths first, then make the smallest local remediation that preserves behavior.

**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g '"'!node_modules'"' -g '"'!vendor'"'"`
```
/work
FINDING.txt

```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** The worktree is clean and the finding file is present at the repo root. I’m opening it now and locating the referenced implementation.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: mvantellingen/python-zeep
Vulnerability type: Server-Side Request Forgery (CWE-918)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  src/zeep/exceptions.py
    - lines 114-116   in: def __init__(self, name, content):

  src/zeep/loader.py
    - lines 5-22
    - lines 45-51   in: def parse_xml(content: str, transport, base_url=None, settings=None):
    - lines 69-75   in: def parse_xml(content: str, transport, base_url=None, settings=None):
    -   …(+468 more chars)
```
**→ shell:** `/bin/bash -lc 'rg --files'`
```
tests/test_settings.py
tests/test_wsdl.py
tests/test_xsd_union.py
tests/test_cache.py
tests/test_xsd_simple_types.py
tests/test_main.py
tests/test_soap_xop.py
tests/test_wsdl_messages_http.py
tests/test_client.py
tests/test_wsdl_messages_document.py
tests/test_xsd_validation.py
tests/test_xsd_parse.py
tests/test_helpers.py
tests/test_wsdl_messages_rpc.py
tests/test_wsa.py
tests/test_xsd_any.py
tests/utils.py
src/zeep/wsa.py
src/zeep/__main__.py
src/zeep/helpers.py
tests/wsdl_files/soap.wsdl
test  …(+4056 more chars)
```
**Codex:** The issue is an SSRF surface in XML parsing and external reference loading. I’m checking the current settings and loader flow so the fix fits Zeep’s existing controls instead of changing how valid imports normally resolve.

**→ shell:** `/bin/bash -lc "nl -ba src/zeep/loader.py | sed -n '1,180p'"`
```
     1	import os.path
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
    12	class ImportResolver(Resolver):
    13	    """Custom lxml resolve to use the transport object"""
    14	
    15	    def __i  …(+6013 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/zeep/wsdl/wsdl.py | sed -n '70,170p'"`
```
    70	            self.location = location
    71	        else:
    72	            self.location = base
    73	
    74	        self.transport = transport
    75	
    76	        # Dict with all definition objects within this WSDL
    77	        self._definitions = (
    78	            {}
    79	        )  # type: typing.Dict[typing.Tuple[str, str], "Definition"]
    80	        self.types = Schema(
    81	            node=None,
    82	            transport=self.transport,
    83	            locat  …(+3326 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/zeep/xsd/schema.py | sed -n '90,145p'"`
```
    90	                    seen.add(element.qname)
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
   102	                if type_.qname not in seen:
   103	                    yield type_
   104	                     …(+1713 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/zeep/settings.py | sed -n '1,120p'"`
```
     1	import threading
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
    14	    :type strict: boolean
    15	    :param raw_response: boolean to skip the parsing of the XML resp  …(+3032 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/zeep/exceptions.py | sed -n '90,140p'"`
```
    90	
    91	
    92	class IncompleteOperation(Error):
    93	    pass
    94	
    95	
    96	class DTDForbidden(Error):
    97	    def __init__(self, name, sysid, pubid):
    98	        super().__init__()
    99	        self.name = name
   100	        self.sysid = sysid
   101	        self.pubid = pubid
   102	
   103	    def __str__(self):
   104	        tpl = "DTDForbidden(name='{}', system_id={!r}, public_id={!r})"
   105	        return tpl.format(self.name, self.sysid, self.pubid)
   106	  …(+360 more chars)
```
**Codex:** `forbid_external` already exists and defaults to `True`, but the parser resolver does not enforce it before fetching HTTP(S) references. I’m checking existing tests and exception patterns so the remediation is covered without widening behavior beyond that setting.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' tests/test_loader.py"`
```
import pytest

from tests.utils import DummyTransport
from zeep.exceptions import DTDForbidden, EntitiesForbidden
from zeep.loader import parse_xml
from zeep.settings import Settings


def test_huge_text():
    # libxml2>=2.7.3 has XML_MAX_TEXT_LENGTH 10000000 without XML_PARSE_HUGE
    settings = Settings(xml_huge_tree=True)
    tree = parse_xml(
        """
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
         <s:Body>
          <HugeText xmlns="http://hugetext">%s<  …(+911 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "ExternalReference|forbid_external|ImportResolver|parse_xml|load_external|DTDForbidden|EntitiesForbidden" -n tests src docs'`
```
tests/test_wsdl.py:10:from zeep.exceptions import DTDForbidden, EntitiesForbidden
tests/test_wsdl.py:968:    with pytest.raises(DTDForbidden):
tests/test_wsdl.py:973:    with pytest.raises(EntitiesForbidden):
src/zeep/wsdl/bindings/soap.py:9:from zeep.loader import parse_xml
src/zeep/wsdl/bindings/soap.py:204:            doc = parse_xml(content, self.transport, settings=client.settings)
src/zeep/wsdl/wsdl.py:17:from zeep.loader import absolute_location, is_relative_path, load_external
src/zeep/w  …(+6333 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' tests/test_settings.py"`
```
from zeep.settings import Settings


def test_settings_set_context_raw_response():
    settings = Settings()

    assert settings.raw_response is False
    with settings(raw_response=True):
        assert settings.raw_response is True

        with settings():
            # Check that raw_response is not changed by default value
            assert settings.raw_response is True
    # Check that the original value returned
    assert settings.raw_response is False


def test_settings_set_context_w  …(+342 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' src/zeep/exceptions.py"`
```
class Error(Exception):
    def __init__(self, message=""):
        super(Exception, self).__init__(message)
        self.message = message

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.message)


class XMLSyntaxError(Error):
    def __init__(self, *args, **kwargs):
        self.content = kwargs.pop("content", None)
        super().__init__(*args, **kwargs)


class XMLParseError(Error):
    def __init__(self, *args, **kwargs):
        self.filename = kwargs.po  …(+2416 more chars)
```
**Codex:** I found the vulnerable fetch: reading `docinfo.externalDTD` can invoke Zeep’s resolver, and the resolver currently calls `transport.load()` for HTTP(S) before honoring `settings.forbid_external`. I’m going to add an explicit external-reference exception, wire the parser resolver to the setting, and add focused tests that assert no outbound load happens by default.

**→ shell:** `/bin/bash -lc "sed -n '930,990p' tests/test_wsdl.py"`
```
    transport = DummyTransport()
    transport.bind("http://tests.python-zeep.org/schema-2.wsdl", wsdl_2)
    document = wsdl.Document(wsdl_main, transport)
    document.dump()


def test_wsdl_dtd_entities_rules():
    wsdl_declaration = """<!DOCTYPE Author [
        <!ENTITY writer "Donald Duck.">
        ]>
        <wsdl:definitions
        xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:tns="http://tests.python-zeep.org/xsd-main  …(+1679 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,200p' tests/utils.py"`
```
from lxml import etree


def load_xml(xml):
    parser = etree.XMLParser(
        remove_blank_text=True, remove_comments=True, resolve_entities=False
    )
    return etree.fromstring(xml.strip(), parser=parser)


def assert_nodes_equal(result, expected):
    def _convert_node(node):
        if isinstance(node, (str, bytes)):
            return load_xml(node)
        return node

    # assert node_1 == node_2
    result = etree.tostring(_convert_node(result), pretty_print=True)
    expected = e  …(+583 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' pyproject.toml"`
```
[project]
name = "zeep"
version = "4.3.2"
description = "A Python SOAP client"
readme = "README.md"
license = { text = "MIT" }
authors = [
    { name = "Michael van Tellingen", email = "michaelvantellingen@gmail.com" }
]
requires-python = ">=3.10"
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
   …(+1793 more chars)
```
**Codex:** I’m editing `exceptions.py` and `loader.py` now. The key behavior change is narrow: parser-level external DTD/entity resolution is denied when `forbid_external` is true, while normal Zeep WSDL/XSD imports still use the existing transport path.

**✎ files:** update `/work/src/zeep/exceptions.py`

**✎ files:** update `/work/src/zeep/loader.py`

**Codex:** The code now denies parser-resolved external references through the existing `forbid_external` setting. I’m adding regression tests around remote and local external DTD references so the SSRF/LFI path stays closed by default.

**✎ files:** update `/work/tests/test_loader.py`

**Codex:** The regression tests are in place. I’m running the loader tests first; if those pass, I’ll run the broader relevant suite around WSDL/settings parsing.

**→ shell:** `/bin/bash -lc 'pytest tests/test_loader.py -q'`
```
/bin/bash: line 1: pytest: command not found

```
**→ shell:** `/bin/bash -lc 'python -m compileall -q src/zeep tests/test_loader.py'`
**Codex:** `pytest` is not installed as a shell command in this environment, but bytecode compilation passed. I’m checking whether the test runner is available as a module and doing a quick direct parser exercise to verify the new exception path.

**→ shell:** `/bin/bash -lc "python - <<'PY'
from zeep.exceptions import ExternalReferenceForbidden
from zeep.loader import parse_xml

class FailingTransport:
    def load(self, url):
        raise AssertionError(u  …(+267 more chars)`
```
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ModuleNotFoundError: No module named 'zeep'

```
**→ shell:** `/bin/bash -lc 'python -m pytest tests/test_loader.py -q'`
```
/usr/local/bin/python: No module named pytest

```
**Codex:** This environment also lacks the `pytest` module, and the package is not installed into the interpreter. I’m rerunning the direct verification with `PYTHONPATH=src` so it exercises the edited source tree.

**→ shell:** `/bin/bash -lc "PYTHONPATH=src python - <<'PY'
from zeep.exceptions import ExternalReferenceForbidden
from zeep.loader import parse_xml

class FailingTransport:
    def load(self, url):
        raise A  …(+374 more chars)`
```
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/work/src/zeep/__init__.py", line 1, in <module>
    from zeep.client import AsyncClient, CachingClient, Client
  File "/work/src/zeep/client.py", line 5, in <module>
    from zeep.settings import Settings
  File "/work/src/zeep/settings.py", line 4, in <module>
    import attr
ModuleNotFoundError: No module named 'attr'

```
**→ shell:** `/bin/bash -lc 'git diff -- src/zeep/exceptions.py src/zeep/loader.py tests/test_loader.py'`
```
diff --git a/src/zeep/exceptions.py b/src/zeep/exceptions.py
index f59d5d1..5286d55 100644
--- a/src/zeep/exceptions.py
+++ b/src/zeep/exceptions.py
@@ -114,3 +114,12 @@ class EntitiesForbidden(Error):
     def __str__(self):
         tpl = "EntitiesForbidden(name='{}', content={!r})"
         return tpl.format(self.name, self.content)
+
+
+class ExternalReferenceForbidden(Error):
+    def __init__(self, url):
+        super().__init__()
+        self.url = url
+
+    def __str__(self):
+         …(+3316 more chars)
```
**Codex:** The direct check is blocked by missing project dependencies (`attrs`, then likely pytest). I also noticed one added assertion is longer than the project’s flake8 limit, so I’m tightening the test assertions before attempting dependency-backed tests.

**✎ files:** update `/work/tests/test_loader.py`

**Codex:** I’m installing the project’s test dependencies into the current environment so the verification runs against the actual source, not a partial import. This only affects the local runtime environment, not the repository files.

**→ shell:** `/bin/bash -lc "python -m pip install -e '.[test]'"`
```
Obtaining file:///work
  Installing build dependencies: started
  Installing build dependencies: finished with status 'error'
  error: subprocess-exited-with-error
  
  × pip subprocess to install build dependencies did not run successfully.
  │ exit code: 1
  ╰─> [7 lines of output]
      WARNING: Retrying (Retry(total=4, connect=None, read=None, redirect=None, status=None)) after connection broken by 'ProxyError('Cannot connect to proxy.', OSError('Tunnel connection failed: 403 blocked by egre  …(+1576 more chars)
```
**Codex:** Dependency installation is blocked by the environment’s package egress policy, so I can’t run the pytest suite here. I’m still going to execute a direct regression check by loading the edited modules with a minimal settings stub, which verifies the lxml resolver path itself.

**→ shell:** `/bin/bash -lc "python - <<'PY'
import importlib.util
import sys
import types

exc_spec = importlib.util.spec_from_file_location('zeep.exceptions', 'src/zeep/exceptions.py')
exceptions = importlib.util  …(+1201 more chars)`
```
Traceback (most recent call last):
  File "<stdin>", line 24, in <module>
  File "<frozen importlib._bootstrap_external>", line 940, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/work/src/zeep/loader.py", line 5, in <module>
    from lxml import etree
ModuleNotFoundError: No module named 'lxml'

```
**Codex:** Because I can’t run lxml locally, I’m making the block deterministic in Zeep’s own control flow too: external DTD system IDs and external entity system URLs are rejected before code asks lxml to load/inspect the external subset. That avoids relying only on resolver propagation.

**✎ files:** update `/work/src/zeep/loader.py`

**Codex:** The remediation now has two layers: Zeep rejects known external declarations before `docinfo.externalDTD` can trigger loading, and the lxml resolver refuses any parser-requested external resource while `forbid_external` is enabled. I’m doing static checks and reviewing the final diff.

**→ shell:** `/bin/bash -lc 'git diff -- src/zeep/exceptions.py src/zeep/loader.py tests/test_loader.py'`
```
diff --git a/src/zeep/exceptions.py b/src/zeep/exceptions.py
index f59d5d1..5286d55 100644
--- a/src/zeep/exceptions.py
+++ b/src/zeep/exceptions.py
@@ -114,3 +114,12 @@ class EntitiesForbidden(Error):
     def __str__(self):
         tpl = "EntitiesForbidden(name='{}', content={!r})"
         return tpl.format(self.name, self.content)
+
+
+class ExternalReferenceForbidden(Error):
+    def __init__(self, url):
+        super().__init__()
+        self.url = url
+
+    def __str__(self):
+         …(+4369 more chars)
```
**→ shell:** `/bin/bash -lc "python - <<'PY'
from pathlib import Path
for path in [Path('src/zeep/loader.py'), Path('src/zeep/exceptions.py'), Path('tests/test_loader.py')]:
    for lineno, line in enumerate(path.r  …(+109 more chars)`
**→ shell:** `/bin/bash -lc 'python -m compileall -q src/zeep tests/test_loader.py'`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/zeep/exceptions.py
 M src/zeep/loader.py
 M tests/test_loader.py

```
**Codex:** Static compilation and line-length checks pass. I can’t run pytest because dependencies cannot be installed from the network in this environment, so I’m doing the final whitespace check and then I’ll summarize exactly what changed.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/zeep/exceptions.py
 M src/zeep/loader.py
 M tests/test_loader.py

```
**Codex:** Implemented the SSRF remediation locally.

Changed:
- [src/zeep/exceptions.py](/work/src/zeep/exceptions.py): added `ExternalReferenceForbidden`.
- [src/zeep/loader.py](/work/src/zeep/loader.py): wired `ImportResolver` to `Settings`, blocks external parser references when `forbid_external=True`, enables lxml `no_network`, and rejects external DTD/entity URLs before `docinfo.externalDTD` can trigger loading.
- [tests/test_loader.py](/work/tests/test_loader.py): added regression tests for HTTP and file external DTD references, asserting `transport.load()` is not called.

Verification:
- `python -m compileall -q src/zeep tests/test_loader.py` passed.
- `git diff --check` passed.
- Could not run pytest because this environment lacks `pytest`, `attrs`, and `lxml`, and `pip install -e '.[test]'` was blocked by the network egress allowlist.


---
*tokens — input 439909 (cached 390400), output 7212, reasoning 2730*
