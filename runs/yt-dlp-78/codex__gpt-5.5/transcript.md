**Codex:** I’ll inspect the vulnerability note first, then trace the affected code paths before editing so the fix stays scoped to the reported issue.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: yt-dlp/yt-dlp
Vulnerability type: OS Command Injection (CWE-78)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  yt_dlp/YoutubeDL.py
    - lines 112-117
    - lines 826-834   in: def check_deprecated(param, option, suggestion):
    - lines 1254-1260   in: def _copy_infodict(info_dict):
    - lines 1305-1310   in: def prepare_outtmpl(self, outtmpl, info_dict, sanitize=False):
    - lines 1429-1434   in: def create_key(outer_mobj):

  yt_dlp/__init  …(+416 more chars)
```
**→ shell:** `/bin/bash -lc 'pwd && rg --files'`
```
/work
supportedsites.md
Makefile
yt-dlp.sh
Changelog.md
yt-dlp.cmd
devscripts/check-porn.py
devscripts/setup_variables.py
devscripts/bash-completion.in
devscripts/zsh-completion.in
devscripts/generate_aes_testdata.py
devscripts/fish-completion.in
devscripts/update_changelog.py
devscripts/prepare_manpage.py
devscripts/utils.py
devscripts/fish-completion.py
devscripts/lazy_load_template.py
devscripts/setup_variables_tests.py
devscripts/zsh-completion.py
devscripts/bash-completion.py
devscripts/tom  …(+37009 more chars)
```
**Codex:** The finding points at several small ranges, likely shared helpers/imports plus the exec postprocessor. I’m reading those exact areas now to identify the actual command boundary instead of changing unrelated behavior.

**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/utils/_utils.py | sed -n '1160,1205p'"`
```
  1160	        # Both in bytes
  1161	        self.downloaded = downloaded
  1162	        self.expected = expected
  1163	
  1164	
  1165	class XAttrMetadataError(YoutubeDLError):
  1166	    def __init__(self, code=None, msg='Unknown error'):
  1167	        super().__init__(msg)
  1168	        self.code = code
  1169	        self.msg = msg
  1170	
  1171	        # Parsing code and msg
  1172	        if (self.code in (errno.ENOSPC, errno.EDQUOT)
  1173	                or 'No space left' in self.m  …(+1554 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/__init__.py | sed -n '30,60p;1055,1095p'"`
```
    30	    FFmpegThumbnailsConvertorPP,
    31	    FFmpegVideoConvertorPP,
    32	    FFmpegVideoRemuxerPP,
    33	    MetadataFromFieldPP,
    34	    MetadataParserPP,
    35	)
    36	from .update import Updater
    37	from .utils import (
    38	    NO_DEFAULT,
    39	    POSTPROCESS_WHEN,
    40	    DateRange,
    41	    DownloadCancelled,
    42	    DownloadError,
    43	    FormatSorter,
    44	    GeoUtils,
    45	    PlaylistEntries,
    46	    SameFileError,
    47	    download_range_fun  …(+2129 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/options.py | sed -n '540,590p;1745,1790p'"`
```
   540	            'stdout': 'no_color',
   541	            'stderr': 'no_color',
   542	        },
   543	        help=optparse.SUPPRESS_HELP)
   544	    general.add_option(
   545	        '--color',
   546	        dest='color', metavar='[STREAM:]POLICY', default={}, type='str',
   547	        action='callback', callback=_dict_from_options_callback,
   548	        callback_kwargs={
   549	            'allowed_keys': 'stdout|stderr',
   550	            'default_key': ['stdout', 'stderr'],
   551  …(+6025 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/postprocessor/exec.py | sed -n '1,220p'"`
```
     1	from .common import PostProcessor
     2	from ..utils import Popen, PostProcessingError, shell_quote, variadic
     3	
     4	
     5	class ExecPP(PostProcessor):
     6	
     7	    def __init__(self, downloader, exec_cmd):
     8	        PostProcessor.__init__(self, downloader)
     9	        self.exec_cmd = variadic(exec_cmd)
    10	
    11	    def parse_cmd(self, cmd, info):
    12	        tmpl, tmpl_dict = self._downloader.prepare_outtmpl(cmd, info)
    13	        if tmpl_dict:  # if   …(+1322 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/YoutubeDL.py | sed -n '90,150p;800,850p;1230,1325p;1410,1450p'"`
```
    90	    OUTTMPL_TYPES,
    91	    POSTPROCESS_WHEN,
    92	    STR_FORMAT_RE_TMPL,
    93	    STR_FORMAT_TYPES,
    94	    ContentTooShortError,
    95	    DateRange,
    96	    DownloadCancelled,
    97	    DownloadError,
    98	    EntryNotInPlaylist,
    99	    ExistingVideoReached,
   100	    ExtractorError,
   101	    FormatSorter,
   102	    GeoRestrictedError,
   103	    ISO3166Utils,
   104	    LazyList,
   105	    MaxDownloadsReached,
   106	    Namespace,
   107	    PagedList,
   10  …(+10913 more chars)
```
**Codex:** The vulnerable path is `--exec`: it builds a single shell command from user templates and video metadata, then runs it with `shell=True`. I’m checking the existing tests and option semantics so the remediation preserves documented shell-command support while preventing metadata from becoming shell syntax.

**→ shell:** `/bin/bash -lc "rg -n \"ExecPP|--exec|exec_cmd|exec-before|postprocessor.*Exec|Executing command|parse_cmd|shell_quote\" test yt_dlp -g '*.py'"`
```
yt_dlp/postprocessor/embedthumbnail.py:16:    shell_quote,
yt_dlp/postprocessor/embedthumbnail.py:165:                    self.write_debug(f'AtomicParsley command line: {shell_quote(cmd)}')
yt_dlp/postprocessor/__init__.py:5:from .exec import ExecAfterDownloadPP, ExecPP
yt_dlp/postprocessor/ffmpeg.py:30:    shell_quote,
yt_dlp/postprocessor/ffmpeg.py:245:            self.write_debug(f'{self.basename} command line: {shell_quote(cmd)}')
yt_dlp/postprocessor/ffmpeg.py:287:        self.write_debug(f  …(+2214 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"def shell_quote|class Popen|shell=True|Popen\\.run\" yt_dlp/utils yt_dlp -g '*.py'"`
```
yt_dlp/extractor/openload.py:236:            stdout, stderr, returncode = Popen.run(cmd, timeout=self.options['timeout'] / 1000,
yt_dlp/extractor/common.py:1398:            stdout, _, ret = Popen.run(cmd, text=True, shell=True, stdout=subprocess.PIPE)

```
**Codex:** There’s also an extractor helper that executes site-provided commands with `shell=True`, so I’m checking whether it shares the same injection pattern or is separate from the reported file list. The reported remediation can be narrower if that path is not reachable from the noted option/template flow.

**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/utils/_utils.py | sed -n '830,910p;1685,1735p'"`
```
   830	        .replace("'", '&#39;')
   831	    )
   832	
   833	
   834	class netrc_from_content(netrc.netrc):
   835	    def __init__(self, content):
   836	        self.hosts, self.macros = {}, {}
   837	        with io.StringIO(content) as stream:
   838	            self._parse('-', stream, False)
   839	
   840	
   841	class Popen(subprocess.Popen):
   842	    if sys.platform == 'win32':
   843	        _startupinfo = subprocess.STARTUPINFO()
   844	        _startupinfo.dwFlags |= subproces  …(+5372 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/extractor/common.py | sed -n '1370,1410p'"`
```
  1370	                raise ExtractorError(
  1371	                    f'Unable to extract {_name} - Failed to parse JSON', cause=e.cause, video_id=video_id)
  1372	            elif not has_default:
  1373	                self.report_warning(
  1374	                    f'Unable to extract {_name} - Failed to parse JSON: {e}', video_id=video_id)
  1375	        return default
  1376	
  1377	    def _html_search_regex(self, pattern, string, name, default=NO_DEFAULT, fatal=True, flags=0, group=None  …(+1838 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba test/test_postprocessors.py | sed -n '60,115p'"`
```
    60	        subprocess.check_call([
    61	            pp.executable, '-y', '-f', 'lavfi', '-i', 'color=c=black:s=320x320',
    62	            '-c:v', 'libwebp', '-pix_fmt', 'yuv420p', '-vframes', '1', generated_file,
    63	        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    64	
    65	        file = test_data_dir + '/foo %d bar/foo_%d.{}'
    66	        initial_file = file.format('webp')
    67	        os.replace(generated_file, initial_file)
    68	
    69	        tests =   …(+1802 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba test/test_utils.py | sed -n '590,615p;2190,2210p'"`
```
   590	
   591	        res_url, res_data = unsmuggle_url(url)
   592	        self.assertEqual(res_url, url)
   593	        self.assertEqual(res_data, None)
   594	
   595	        smug_url = smuggle_url(url, {'a': 'b'})
   596	        smug_smug_url = smuggle_url(smug_url, {'c': 'd'})
   597	        res_url, res_data = unsmuggle_url(smug_smug_url)
   598	        self.assertEqual(res_url, url)
   599	        self.assertEqual(res_data, {'a': 'b', 'c': 'd'})
   600	
   601	    def test_shell_quote(se  …(+1840 more chars)
```
**Codex:** The template engine already has a `%(... )q` conversion that shell-quotes values, but `--exec` currently does not require or default to it. I’m looking at the formatter internals to add shell quoting after normal field formatting, which keeps width/default/replacement behavior intact.

**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/YoutubeDL.py | sed -n '1257,1468p'"`
```
  1257	    def prepare_outtmpl(self, outtmpl, info_dict, sanitize=False):
  1258	        """ Make the outtmpl and info_dict suitable for substitution: ydl.escape_outtmpl(outtmpl) % info_dict
  1259	        @param sanitize    Whether to sanitize the output as a filename
  1260	        """
  1261	
  1262	        info_dict.setdefault('epoch', int(time.time()))  # keep epoch consistent once set
  1263	
  1264	        info_dict = self._copy_infodict(info_dict)
  1265	        info_dict['duration_strin  …(+10961 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"prepare_outtmpl\\(|escape_outtmpl\\(|%\\)q|fmt\\[-1\\] == 'q'\" yt_dlp test -g '*.py'"`
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/YoutubeDL.py | sed -n '1468,1500p'"`
```
  1468	                value = float_or_none(value)
  1469	                if value is None:
  1470	                    value, fmt = default, 's'
  1471	
  1472	            if sanitize:
  1473	                # If value is an object, sanitize might convert it to a string
  1474	                # So we manually convert it before sanitizing
  1475	                if fmt[-1] == 'r':
  1476	                    value, fmt = repr(value), str_fmt
  1477	                elif fmt[-1] == 'a':
  1478	       …(+1318 more chars)
```
**Codex:** I’ve got a contained fix: add an opt-in shell-quoting mode to the output-template formatter, then use it only for `--exec`. Literal command text remains shell syntax, but substituted metadata is emitted as shell-escaped arguments by default.

**→ shell:** `/bin/bash -lc "rg -n \"def assertEqual|assertEqual\\(|parse_cmd\" test/helper.py test -g '*.py' | head -60"`
```
test/helper.py:351:def assertEqual(self, got, expected, msg=None):
test/test_cache.py:44:        self.assertEqual(c.load('test_cache', 'k.'), None)
test/test_cache.py:46:        self.assertEqual(c.load('test_cache', 'k2'), None)
test/test_cache.py:48:        self.assertEqual(c.load('test_cache', 'k.'), obj)
test/test_cache.py:49:        self.assertEqual(c.load('test_cache', 'y'), None)
test/test_cache.py:50:        self.assertEqual(c.load('test_cache2', 'k.'), None)
test/test_cache.py:53:         …(+5613 more chars)
```
**Codex:** I’m going to patch the formatter with a new keyword argument and update the exec postprocessor tests with a command-injection regression case. The change is deliberately opt-in so normal filename/output templates are unaffected.

**✎ files:** update `/work/test/test_postprocessors.py`, update `/work/yt_dlp/YoutubeDL.py`, update `/work/yt_dlp/postprocessor/exec.py`

**Codex:** The patch is in place. I’m running the focused postprocessor tests first, then I’ll do a quick formatter sanity check because this touches a shared template function through an opt-in branch.

**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/YoutubeDL.py | sed -n '1428,1490p'"`
```
  1428	
  1429	            fmt = outer_mobj.group('format')
  1430	            if fmt == 's' and last_field in field_size_compat_map and isinstance(value, int):
  1431	                fmt = f'0{field_size_compat_map[last_field]:d}d'
  1432	
  1433	            flags = outer_mobj.group('conversion') or ''
  1434	            str_fmt = f'{fmt[:-1]}s'
  1435	            if value is None:
  1436	                value, fmt = default, 's'
  1437	            elif fmt[-1] == 'l':  # list
  1438	            …(+3027 more chars)
```
**→ shell:** `/bin/bash -lc 'python -m pytest test/test_postprocessors.py::TestExec -q'`
```
/usr/local/bin/python: No module named pytest

```
**Codex:** `pytest` is not installed in this environment, so I’m switching to the repository’s unittest-compatible path for the focused tests and a direct runtime check.

**→ shell:** `/bin/bash -lc "python - <<'PY'
from yt_dlp import YoutubeDL
from yt_dlp.postprocessor.exec import ExecPP
from yt_dlp.utils import shell_quote
pp = ExecPP(YoutubeDL(), '')
info = {'filepath': 'file nam  …(+283 more chars)`
```
Traceback (most recent call last):
  File "<stdin>", line 7, in <module>
  File "/work/yt_dlp/postprocessor/exec.py", line 12, in parse_cmd
echo 'a; touch injected'
    tmpl, tmpl_dict = self._downloader.prepare_outtmpl(cmd, info, shell_quote_fields=True)
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/work/yt_dlp/YoutubeDL.py", line 1504, in prepare_outtmpl
    return EXTERNAL_FORMAT_RE.sub(create_key, outtmpl), TMPL_DICT
           ^^^^^^^^^^  …(+265 more chars)
```
**→ shell:** `/bin/bash -lc 'python -m unittest test.test_postprocessors.TestExec'`
```
EE
======================================================================
ERROR: test_parse_cmd (test.test_postprocessors.TestExec.test_parse_cmd)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/work/test/test_postprocessors.py", line 92, in test_parse_cmd
    self.assertEqual(pp.parse_cmd('echo %(filepath)q', info), cmd)
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/work/yt_dlp/postprocessor/exec.py", lin  …(+1862 more chars)
```
**Codex:** The first focused run exposed a small bug in the skip-double-quote branch for explicit `%(... )q`. I’m fixing that and rerunning the same checks.

**✎ files:** update `/work/yt_dlp/YoutubeDL.py`

**→ shell:** `/bin/bash -lc "python - <<'PY'
from yt_dlp import YoutubeDL
from yt_dlp.postprocessor.exec import ExecPP
from yt_dlp.utils import shell_quote
pp = ExecPP(YoutubeDL(), '')
info = {'filepath': 'file nam  …(+283 more chars)`
```
echo 'a; touch injected'
echo 'a; touch injected'
echo 007
'a; touch injected'

```
**→ shell:** `/bin/bash -lc 'python -m unittest test.test_postprocessors.TestExec'`
```
..
----------------------------------------------------------------------
Ran 2 tests in 0.835s

OK

```
**Codex:** I noticed a subtle formatter edge case: precision/width could be applied after quoting, which can truncate quote characters. I’m tightening the implementation so normal formatting is applied first, then the completed field value is shell-quoted as a whole.

**✎ files:** update `/work/yt_dlp/YoutubeDL.py`

**Codex:** I’m checking the patched block immediately because generator comprehensions with conditional iterables are easy to get syntactically wrong.

**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/YoutubeDL.py | sed -n '1440,1500p'"`
```
  1440	            elif fmt[-1] == 'j':  # json
  1441	                value, fmt = json.dumps(
  1442	                    value, default=_dumpjson_default,
  1443	                    indent=4 if '#' in flags else None, ensure_ascii='+' not in flags), str_fmt
  1444	            elif fmt[-1] == 'h':  # html
  1445	                value, fmt = escapeHTML(str(value)), str_fmt
  1446	            fmt_type = fmt[-1]
  1447	            if fmt_type == 'q':  # quoted
  1448	                value = (
  14  …(+2913 more chars)
```
**→ shell:** `/bin/bash -lc 'python -m py_compile yt_dlp/YoutubeDL.py yt_dlp/postprocessor/exec.py test/test_postprocessors.py'`
```
  File "yt_dlp/YoutubeDL.py", line 1450
    for item in variadic(value) if '#' in flags else [value])
                                                ^^^^
SyntaxError: invalid syntax

```
**Codex:** The syntax check caught the conditional iterable issue. I’m correcting that now, then I’ll rerun compile and focused tests.

**✎ files:** update `/work/yt_dlp/YoutubeDL.py`

**→ shell:** `/bin/bash -lc 'python -m py_compile yt_dlp/YoutubeDL.py yt_dlp/postprocessor/exec.py test/test_postprocessors.py'`
**→ shell:** `/bin/bash -lc "python - <<'PY'
from yt_dlp import YoutubeDL
from yt_dlp.postprocessor.exec import ExecPP
pp = ExecPP(YoutubeDL(), '')
info = {'filepath': 'file name', 'title': 'abc; touch injected', '  …(+208 more chars)`
```
echo 'abc; touch injected'
echo 'abc; touch injected'
echo abc
echo abc
echo 007

```
**→ shell:** `/bin/bash -lc 'python -m unittest test.test_postprocessors.TestExec'`
```
..
----------------------------------------------------------------------
Ran 2 tests in 1.299s

OK

```
**Codex:** The focused tests pass now. I’m running the broader postprocessor file and template-related unit tests to catch regressions around `%(... )q` and normal output templates.

**→ shell:** `/bin/bash -lc 'python -m unittest test.test_YoutubeDL test.test_utils.TestUtil.test_shell_quote'`
```
[debug] Formats sorted by: hasvid, ie_pref, lang, quality, res, fps, hdr:12(7), vcodec, channels, acodec, size, br, asr, proto, vext, aext, hasaud, source, id
[debug] Formats sorted by: hasvid, ie_pref, lang, quality, res, fps, hdr:12(7), vcodec, channels, acodec, size, br, asr, proto, vext, aext, hasaud, source, id
...[debug] Sort order given by extractor: id
[debug] Formats sorted by: hasvid, ie_pref, id, lang, quality, res, fps, hdr:12(7), vcodec, channels, acodec, size, br, asr, proto, vext,  …(+92699 more chars)
```
**→ shell:** `/bin/bash -lc 'python -m unittest test.test_postprocessors'`
```
.........................................................
----------------------------------------------------------------------
Ran 57 tests in 2.802s

OK
Skipping: ffmpeg not found

```
**Codex:** The broader checks passed. I’m checking the worktree now for only the intended source/test edits and any test artifacts that need cleanup.

**→ shell:** `/bin/bash -lc 'git diff -- yt_dlp/YoutubeDL.py yt_dlp/postprocessor/exec.py test/test_postprocessors.py'`
```
diff --git a/test/test_postprocessors.py b/test/test_postprocessors.py
index d58a97f..4fdc5dc 100644
--- a/test/test_postprocessors.py
+++ b/test/test_postprocessors.py
@@ -91,6 +91,17 @@ def test_parse_cmd(self):
         self.assertEqual(pp.parse_cmd('echo {}', info), cmd)
         self.assertEqual(pp.parse_cmd('echo %(filepath)q', info), cmd)
 
+    def test_parse_cmd_shell_quote_fields(self):
+        pp = ExecPP(YoutubeDL(), '')
+        info = {'filepath': 'file name', 'title': 'a; touch i  …(+5043 more chars)
```
**→ shell:** `/bin/bash -lc "ls -la | rg 'test_infojson|post-processor-testfile|\\.info\\.json|\\.mp4"'$'"'"`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M test/test_postprocessors.py
 M yt_dlp/YoutubeDL.py
 M yt_dlp/postprocessor/exec.py

```
**→ shell:** `/bin/bash -lc "rg -n \"STR_FORMAT_RE_TMPL|STR_FORMAT_TYPES\" yt_dlp -g '*.py'"`
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/utils/_utils.py | sed -n '2870,2895p'"`
```
  2870	    'pl_infojson': 'info.json',
  2871	}
  2872	
  2873	# As of [1] format syntax is:
  2874	#  %[mapping_key][conversion_flags][minimum_width][.precision][length_modifier]type
  2875	# 1. https://docs.python.org/2/library/stdtypes.html#string-formatting
  2876	STR_FORMAT_RE_TMPL = r'''(?x)
  2877	    (?<!%)(?P<prefix>(?:%%)*)
  2878	    %
  2879	    (?P<has_key>\((?P<key>{0})\))?
  2880	    (?P<format>
  2881	        (?P<conversion>[#0\-+ ]+)?
  2882	        (?P<min_width>\d+)?
  2883	    …(+338 more chars)
```
**Codex:** The worktree contains only the three intended modified files. I’m grabbing final line references for the summary now.

**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/YoutubeDL.py | sed -n '1254,1264p;1442,1498p'"`
```
  1254	        info_dict.pop('__pending_error', None)
  1255	        return info_dict
  1256	
  1257	    def prepare_outtmpl(self, outtmpl, info_dict, sanitize=False, shell_quote_fields=False):
  1258	        """ Make the outtmpl and info_dict suitable for substitution: ydl.escape_outtmpl(outtmpl) % info_dict
  1259	        @param sanitize    Whether to sanitize the output as a filename
  1260	        @param shell_quote_fields    Whether to shell-quote substituted fields
  1261	        """
  126  …(+3309 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba yt_dlp/postprocessor/exec.py | sed -n '1,35p'"`
```
     1	from .common import PostProcessor
     2	from ..utils import Popen, PostProcessingError, shell_quote, variadic
     3	
     4	
     5	class ExecPP(PostProcessor):
     6	
     7	    def __init__(self, downloader, exec_cmd):
     8	        PostProcessor.__init__(self, downloader)
     9	        self.exec_cmd = variadic(exec_cmd)
    10	
    11	    def parse_cmd(self, cmd, info):
    12	        tmpl, tmpl_dict = self._downloader.prepare_outtmpl(cmd, info, shell_quote_fields=True)
    13	     …(+1030 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba test/test_postprocessors.py | sed -n '84,108p'"`
```
    84	class TestExec(unittest.TestCase):
    85	    def test_parse_cmd(self):
    86	        pp = ExecPP(YoutubeDL(), '')
    87	        info = {'filepath': 'file name'}
    88	        cmd = 'echo {}'.format(shell_quote(info['filepath']))
    89	
    90	        self.assertEqual(pp.parse_cmd('echo', info), cmd)
    91	        self.assertEqual(pp.parse_cmd('echo {}', info), cmd)
    92	        self.assertEqual(pp.parse_cmd('echo %(filepath)q', info), cmd)
    93	
    94	    def test_parse_cmd_she  …(+625 more chars)
```
**Codex:** Implemented the remediation for the reported command injection path.

Changed:
- [yt_dlp/YoutubeDL.py](/work/yt_dlp/YoutubeDL.py:1257): added opt-in `shell_quote_fields` handling for output templates.
- [yt_dlp/postprocessor/exec.py](/work/yt_dlp/postprocessor/exec.py:12): `--exec` template substitutions now shell-quote metadata fields before running through `shell=True`.
- [test/test_postprocessors.py](/work/test/test_postprocessors.py:94): added regression coverage for shell metacharacters in substituted fields.

Verified with:
- `python -m py_compile yt_dlp/YoutubeDL.py yt_dlp/postprocessor/exec.py test/test_postprocessors.py`
- `python -m unittest test.test_postprocessors`
- `python -m unittest test.test_YoutubeDL test.test_utils.TestUtil.test_shell_quote`

`pytest` is not installed in this environment, so I used the project’s unittest-compatible test path.


---
*tokens — input 1066064 (cached 997120), output 8066, reasoning 2958*
