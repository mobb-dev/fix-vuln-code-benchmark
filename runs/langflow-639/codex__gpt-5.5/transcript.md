**Codex:** I’ll read the finding and inspect the referenced code before editing, then patch the smallest source area that removes the vulnerability without changing behavior.

**→ shell:** `/bin/bash -lc 'pwd && ls'`
```
/work
AGENTS-example.md
AGENTS.md
CLAUDE.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
DEVELOPMENT.md
FINDING.txt
LICENSE
Makefile
Makefile.frontend
README.md
RELEASE.md
SECURITY.md
ci-skip-analysis.md
codecov.yml
deploy
docker
docker_example
docs
package-lock.json
package.json
pyproject.toml
render.yaml
scripts
src
test-results
uv.lock

```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: langflow-ai/langflow
Vulnerability type: Authorization Bypass Through User-Controlled Key (CWE-639)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  src/backend/base/langflow/api/v1/endpoints.py
    - lines 412-417   in: async def check_flow_user_permission(
    - lines 556-562   in: async def on_disconnect() -> None:
    - lines 616-622   in: async def simplified_run_flow(
    - lines 826-832   in: async def webhook_run_flow(

  src/backend/base  …(+117 more chars)
```
**Codex:** I’m using the `backend-code-review` skill because this is a backend security fix in `src/backend`; I’ll apply its checklist while keeping the change focused.

**→ shell:** `/bin/bash -lc "sed -n '1,240p' /work/.agents/skills/backend-code-review/SKILL.md"`
```
---
name: backend-code-review
description: Review backend code for quality, security, maintainability, and best practices based on established checklist rules. Use when the user requests a review, analysis, or improvement of backend files (e.g., `.py`) under the `src/backend/` directory. Do NOT use for frontend files (e.g., `.tsx`, `.ts`, `.js`). Supports pending-change review, code snippets review, and file-focused review.
---

# Backend Code Review

## When to use this skill

Use this skill wh  …(+13392 more chars)
```
**Codex:** The finding points to flow execution paths and helper-derived argument names, so I’m checking how endpoint identifiers are resolved and where ownership checks are supposed to happen.

**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/helpers/flow.py | sed -n '340,450p'"`
```
   340	
   341	    Returns:
   342	        Tuple[Callable, BaseModel]: A tuple containing the dynamic function and the schema.
   343	    """
   344	    flow_id = flow_data.id
   345	    inputs = get_flow_inputs(graph)
   346	    dynamic_flow_function = generate_function_for_flow(inputs, flow_id, user_id=user_id)
   347	    schema = build_schema_from_inputs(flow_data.name, inputs)
   348	    return dynamic_flow_function, schema
   349	
   350	
   351	def get_flow_inputs(graph: Graph) -> list[Ver  …(+4270 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/v1/endpoints.py | sed -n '360,880p'"`
```
   360	    Args:
   361	        flow (Flow): The flow to execute
   362	        input_request (SimplifiedAPIRequest): The input parameters for the flow
   363	        api_key_user (User | None): Optional authenticated user running the flow
   364	        event_manager (EventManager): Manages the streaming of events to the client
   365	        client_consumed_queue (asyncio.Queue): Tracks client consumption of events
   366	        context (dict | None): Optional context to pass to the flow
   3  …(+25016 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"check_flow_user_permission|get_arg_names|webhook_run_flow|simplified_run_flow|endpoint_name\" src/backend/base/langflow src/backend/tests -g '*.py'"`
```
src/backend/tests/unit/api/v2/test_workflow.py:363:        # Mock get_flow_by_id_or_endpoint_name to raise OperationalError
src/backend/tests/unit/api/v2/test_workflow.py:364:        with patch("langflow.api.v2.workflow.get_flow_by_id_or_endpoint_name") as mock_get_flow:
src/backend/tests/unit/api/v2/test_workflow.py:1427:            patch("langflow.api.v2.workflow.get_flow_by_id_or_endpoint_name") as mock_get_flow,
src/backend/tests/unit/api/utils/test_export_normalisation.py:67:        "endpoi  …(+27624 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/helpers/user.py | sed -n '1,80p'"`
```
     1	from uuid import UUID
     2	
     3	from fastapi import HTTPException
     4	from lfx.services.deps import session_scope_readonly
     5	from sqlmodel import select
     6	
     7	from langflow.services.database.models.flow.model import Flow
     8	from langflow.services.database.models.user.model import User, UserRead
     9	
    10	
    11	async def get_user_by_flow_id_or_endpoint_name(flow_id_or_name: str) -> UserRead | None:
    12	    async with session_scope_readonly() as session:
  …(+751 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/v1/endpoints.py | sed -n '1,120p;880,980p'"`
```
     1	from __future__ import annotations
     2	
     3	import asyncio
     4	import json
     5	import time
     6	from collections.abc import AsyncGenerator
     7	from http import HTTPStatus
     8	from typing import TYPE_CHECKING, Annotated
     9	from uuid import uuid4
    10	
    11	import orjson
    12	import sqlalchemy as sa
    13	from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Request, UploadFile, status
    14	from fastapi.encoders import jsonable_encode  …(+10102 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/services/auth/service.py | sed -n '360,455p'"`
```
   360	            msg = "Invalid token format"
   361	            raise AuthInvalidTokenError(msg)
   362	
   363	        # Use internal authentication method
   364	        return await self._authenticate_with_token(resolved_token, db)
   365	
   366	    async def get_current_user_for_websocket(
   367	        self,
   368	        token: str | None,
   369	        api_key: str | None,
   370	        db: AsyncSession,
   371	    ) -> User | UserRead:
   372	        """Delegates to authenticate_  …(+4158 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/tests/unit/test_webhook.py | sed -n '1,230p'"`
```
     1	import asyncio
     2	from unittest.mock import patch
     3	
     4	import aiofiles
     5	import anyio
     6	import pytest
     7	from langflow.services.event_manager import WebhookEventManager
     8	
     9	
    10	@pytest.fixture(autouse=True)
    11	def _check_openai_api_key_in_environment_variables():
    12	    pass
    13	
    14	
    15	# =============================================================================
    16	# SUCCESS TESTS
    17	# ===============================  …(+10729 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/tests/conftest.py | sed -n '1,220p;600,720p;720,860p'"`
```
     1	import asyncio
     2	import json
     3	import shutil
     4	
     5	# we need to import tmpdir
     6	import tempfile
     7	from collections.abc import AsyncGenerator
     8	from contextlib import suppress
     9	from pathlib import Path
    10	from uuid import UUID, uuid4
    11	
    12	import anyio
    13	import orjson
    14	import pytest
    15	from asgi_lifespan import LifespanManager
    16	from blockbuster import blockbuster_ctx
    17	from dotenv import load_dotenv
    18	from   …(+21419 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"created_api_key|logged_in_headers|logged_in_headers_2|user_2|active_user|normal_user|add.*flow|endpoint_name\" src/backend/tests/conftest.py src/backend/tests/unit/api/v1/test_f  …(+41 more chars)`
```
src/backend/tests/unit/test_chat_endpoint.py:23:async def test_build_flow(client, json_memory_chatbot_no_llm, logged_in_headers):
src/backend/tests/unit/test_chat_endpoint.py:26:    flow_id = await create_flow(client, json_memory_chatbot_no_llm, logged_in_headers)
src/backend/tests/unit/test_chat_endpoint.py:29:    build_response = await build_flow(client, flow_id, logged_in_headers)
src/backend/tests/unit/test_chat_endpoint.py:34:    events_response = await get_build_events(client, job_id, logg  …(+12353 more chars)
```
**Codex:** The vulnerable pattern is the unscoped endpoint-name lookup: endpoint names are only unique per user, but some execution paths resolve by name before tying the lookup to the authenticated user. I’m going to make authenticated run endpoints resolve the flow through the caller’s user id and make webhook auth resolve owner and flow consistently.

**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/utils.py | sed -n '1,180p'"`
```
nl: src/backend/base/langflow/api/utils.py: No such file or directory

```
**→ shell:** `/bin/bash -lc "rg -n \"CurrentActiveUser|def api_key_security|api_key_security|get_current_active_user\" src/backend/base/langflow/api src/backend/base/langflow/services/auth -g '*.py'"`
```
src/backend/base/langflow/services/auth/utils.py:133:async def api_key_security(
src/backend/base/langflow/services/auth/utils.py:137:    return await _auth_service().api_key_security(query_param, header_param)
src/backend/base/langflow/services/auth/utils.py:140:async def ws_api_key_security(api_key: str | None) -> UserRead:
src/backend/base/langflow/services/auth/utils.py:141:    return await _auth_service().ws_api_key_security(api_key)
src/backend/base/langflow/services/auth/utils.py:297:asyn  …(+22257 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/services/auth/utils.py | sed -n '1,180p'"`
```
     1	from __future__ import annotations
     2	
     3	import base64
     4	import random
     5	from typing import TYPE_CHECKING, Annotated, Final
     6	
     7	from cryptography.fernet import Fernet
     8	from fastapi import Depends, HTTPException, Request, Security, WebSocket, WebSocketException, status
     9	from fastapi.security import APIKeyHeader, APIKeyQuery, OAuth2PasswordBearer
    10	from fastapi.security.utils import get_authorization_scheme_param
    11	from lfx.log.logger impo  …(+7575 more chars)
```
**Codex:** I found a second helper with the same unscoped endpoint-name lookup for webhook owner resolution. I’m including that in the fix because otherwise authenticated webhook checks could still authorize against the wrong duplicate endpoint name.

**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/utils/core.py | sed -n '1,60p'"`
```
     1	from __future__ import annotations
     2	
     3	import json as _json
     4	from datetime import timedelta
     5	from enum import Enum
     6	from typing import TYPE_CHECKING, Annotated, Any
     7	
     8	from fastapi import Depends, HTTPException, Path, Query
     9	from fastapi_pagination import Params
    10	from lfx.log.logger import logger
    11	from lfx.services.deps import injectable_session_scope, injectable_session_scope_readonly
    12	from lfx.utils.validate_cloud import r  …(+2402 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/services/database/models/flow/model.py | sed -n '1,110p;200,225p'"`
```
     1	# Path: src/backend/langflow/services/database/models/flow/model.py
     2	
     3	import re
     4	from datetime import datetime, timezone
     5	from enum import Enum
     6	from typing import TYPE_CHECKING, Optional
     7	from uuid import UUID, uuid4
     8	
     9	import emoji
    10	from emoji import purely_emoji
    11	from lfx.log.logger import logger
    12	from pydantic import BaseModel, ValidationInfo, field_serializer, field_validator
    13	from sqlalchemy import Enum as SQLE  …(+5610 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"get_user_by_flow_id_or_endpoint_name\\(\" src/backend/base src/backend/tests -g '*.py'"`
```
src/backend/base/langflow/api/utils/flow_utils.py:191:        user = await get_user_by_flow_id_or_endpoint_name(str(flow_id))
src/backend/base/langflow/api/v1/flows.py:207:    current_user = await get_user_by_flow_id_or_endpoint_name(str(flow_id))

```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/utils/flow_utils.py | sed -n '160,210p'"`
```
   160	    Returns:
   161	        tuple: (flow owner user, deterministic flow ID for tracking)
   162	
   163	    Raises:
   164	        HTTPException:
   165	            - 400 if neither client_id nor authenticated_user_id is provided
   166	            - 403 if flow doesn't exist or isn't public
   167	            - 403 if unable to retrieve the flow owner user
   168	            - 403 if user is not found for public flow
   169	    """
   170	    if not client_id and not authenticated_user_i  …(+1498 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/v1/flows.py | sed -n '180,225p'"`
```
   180	
   181	
   182	@router.get("/{flow_id}", response_model=FlowRead, status_code=200)
   183	async def read_flow(
   184	    *,
   185	    session: DbSession,
   186	    flow_id: UUID,
   187	    current_user: CurrentActiveUser,
   188	):
   189	    """Read a flow."""
   190	    if user_flow := await _read_flow(session, flow_id, current_user.id):
   191	        # Convert to FlowRead while session is still active to avoid detached instance errors
   192	        return FlowRead.model_validate  …(+1423 more chars)
```
**Codex:** Before editing, I’m removing dependency-time flow resolution from webhook because the authenticated identity is not known until the webhook auth policy runs. For normal API-key/session run routes, I’m adding owner-scoped dependency wrappers so duplicate endpoint names resolve within the caller’s account.

**→ shell:** `/bin/bash -lc "rg -n \"def simple_run_flow_task|def simple_run_flow\\(\" src/backend/base/langflow -g '*.py'"`
**→ shell:** `/bin/bash -lc "nl -ba src/backend/base/langflow/api/v1/endpoints.py | sed -n '140,260p'"`
```
   140	            if request_has_input and input_request.input_type == "chat":
   141	                msg = "If you pass an input_value to the chat input, you cannot pass a tweak with the same name."
   142	                raise InvalidChatInputError(msg)
   143	
   144	        elif (
   145	            any(text_key in key for text_key in ("TextInput", "Text Input"))
   146	            and request_has_input
   147	            and input_request.input_type == "text"
   148	        ):
   149	       …(+4816 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/backend/tests/unit/helpers/test_flow.py | sed -n '1,180p'"`
```
     1	"""Unit tests for the langflow.helpers.flow module."""
     2	
     3	import pytest
     4	from lfx.utils.langflow_utils import has_langflow_memory
     5	
     6	# Globals
     7	
     8	_LANGFLOW_HELPER_MODULE_FLOW = "langflow.helpers.flow"
     9	
    10	# Helper Functions
    11	
    12	
    13	def is_helper_module(module, module_name):
    14	    return module.__module__ == module_name
    15	
    16	
    17	# Test Scenarios
    18	
    19	
    20	class TestDynamicImport:
    21	      …(+3519 more chars)
```
**Codex:** I’m applying the source changes now: scoped flow dependencies in `endpoints.py`, optional owner scoping in the user helper, and regression tests for duplicate endpoint names across users.

**✎ files:** update `/work/src/backend/base/langflow/api/v1/endpoints.py`

**Codex:** The route layer is now resolving authenticated run requests through user-scoped lookup wrappers. Next I’m tightening the webhook owner helper so its authorization decision can also be scoped once an API key has identified the caller.

**✎ files:** update `/work/src/backend/base/langflow/helpers/user.py`

**Codex:** I noticed the helper needs to normalize string user ids before comparing UUID fields, so I’m cleaning that up before adding tests.

**✎ files:** update `/work/src/backend/base/langflow/helpers/user.py`

**Codex:** The helper now supports owner scoping. I’m updating webhook auth to use that scoped mode after validating the API key, which keeps the authorization decision tied to the same user that will run the flow.

**✎ files:** update `/work/src/backend/base/langflow/services/auth/service.py`

**Codex:** While adding regression coverage, I found the shared flow helper accepted `user_id` for UUID lookups but only applied it to endpoint-name lookups. I’m fixing that too so all scoped callers get the same ownership guarantee.

**✎ files:** update `/work/src/backend/base/langflow/helpers/flow.py`

**Codex:** I’m adding targeted helper tests rather than broad endpoint tests: they exercise the central lookup rule that the run routes and v2 callers rely on, including duplicate endpoint names and cross-user UUID access.

**✎ files:** update `/work/src/backend/tests/unit/helpers/test_flow.py`

**Codex:** The patch is in place. I’m checking the diff and then I’ll run the narrow helper tests plus a syntax/import check for the edited endpoint module.

**→ shell:** `/bin/bash -lc 'git diff -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/auth/ser  …(+52 more chars)`
```
diff --git a/src/backend/base/langflow/api/v1/endpoints.py b/src/backend/base/langflow/api/v1/endpoints.py
index 1781b0b..6964b2b 100644
--- a/src/backend/base/langflow/api/v1/endpoints.py
+++ b/src/backend/base/langflow/api/v1/endpoints.py
@@ -412,6 +412,22 @@ async def check_flow_user_permission(
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to run this flow")
 
 
+async def get_flow_by_id_or_endpoint_name_for_api_key(
+    flow_id_or_na  …(+8950 more chars)
```
**→ shell:** `/bin/bash -lc 'python -m py_compile src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services  …(+17 more chars)`
**Codex:** The diff looks scoped and the edited modules compile. I’m tightening the test assertion to expect the exact FastAPI exception type, then I’ll run the targeted tests.

**✎ files:** update `/work/src/backend/tests/unit/helpers/test_flow.py`

**Codex:** The tests now assert the precise 404 path. I’m running the focused helper test file with `uv run pytest`; if that passes, I’ll run a formatter/check on the touched backend files.

**→ shell:** `/bin/bash -lc 'uv run pytest src/backend/tests/unit/helpers/test_flow.py'`
```
   Building langflow-base @ file:///work/src/backend/base
   Building lfx @ file:///work/src/lfx
   Building langflow @ file:///work
   Building langflow-sdk @ file:///work/src/sdk
  × Failed to download `cryptography==46.0.7`
  ├─▶ Request failed after 3 retries in 5.5s
  ├─▶ Failed to fetch:
  │   `https://files.pythonhosted.org/packages/36/5f/313586c3be5a2fbe87e4c9a254207b860155a8e1f3cca99f9910008e7d08/cryptography-46.0.7-cp311-abi3-manylinux_2_34_aarch64.whl`
  ├─▶ error sending request for   …(+379 more chars)
```
**Codex:** The targeted pytest run did not reach tests because `uv` had to build a fresh environment and failed downloading `cryptography` from PyPI due to a tunnel connection error. I’ll still run local static checks that don’t need dependency resolution, and I’ll inspect whether an existing environment is available.

**→ shell:** `/bin/bash -lc 'ls -la .venv 2>/dev/null || true'`
```
total 12
drwxr-xr-x  9 root root  288 Jun 30 20:32 .
drwxrwxrwx 45 root root 1440 Jun 30 20:32 ..
-rw-r--r--  1 root root    1 Jun 30 20:32 .gitignore
-rw-rw-rw-  1 root root    0 Jun 30 20:32 .lock
-rw-r--r--  1 root root   43 Jun 30 20:32 CACHEDIR.TAG
drwxr-xr-x 14 root root  448 Jun 30 20:32 bin
drwxr-xr-x  3 root root   96 Jun 30 20:32 lib
lrwxr-xr-x  1 root root    3 Jun 30 20:32 lib64 -> lib
-rw-r--r--  1 root root  138 Jun 30 20:32 pyvenv.cfg

```
**→ shell:** `/bin/bash -lc 'python -m compileall -q src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/servi  …(+64 more chars)`
**→ shell:** `/bin/bash -lc 'git diff --check -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/  …(+60 more chars)`
**Codex:** Compile and whitespace checks passed. The `.venv` exists but was just created by the failed `uv` run, so I’m checking whether it has enough installed to run the focused tests or formatter without another network fetch.

**→ shell:** `/bin/bash -lc '.venv/bin/python -m pytest --version'`
```
/work/.venv/bin/python: No module named pytest

```
**→ shell:** `/bin/bash -lc '.venv/bin/python -m ruff --version'`
```
/work/.venv/bin/python: No module named ruff

```
**→ shell:** `/bin/bash -lc ".venv/bin/python - <<'PY'
try:
    import fastapi, sqlmodel, langflow
    print('imports ok')
except Exception as exc:
    print(type(exc).__name__, exc)
PY"`
```
ModuleNotFoundError No module named 'fastapi'

```
**Codex:** The temporary `.venv` is incomplete and not useful for verification, so I’m removing that generated environment and any bytecode artifacts from the local compile check before finalizing the source diff.

**→ shell:** `/bin/bash -lc 'rm -rf .venv && find src/backend/base/langflow/api/v1 src/backend/base/langflow/helpers src/backend/base/langflow/services/auth src/backend/tests/unit/helpers -type d -name __pycache__   …(+7 more chars)`
```
src/backend/base/langflow/api/v1/__pycache__
src/backend/base/langflow/helpers/__pycache__
src/backend/base/langflow/services/auth/__pycache__
src/backend/tests/unit/helpers/__pycache__

```
**→ shell:** `/bin/bash -lc 'find src/backend/base/langflow/api/v1 src/backend/base/langflow/helpers src/backend/base/langflow/services/auth src/backend/tests/unit/helpers -type d -name __pycache__ -prune -exec rm   …(+9 more chars)`
**Codex:** Generated artifacts are cleaned up. I’m doing a final status/diff pass to make sure only the intended source and test files changed.

**→ shell:** `/bin/bash -lc 'git diff --stat -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/a  …(+59 more chars)`
```
 src/backend/base/langflow/api/v1/endpoints.py      | 24 ++++++--
 src/backend/base/langflow/helpers/flow.py          |  6 +-
 src/backend/base/langflow/helpers/user.py          |  7 ++-
 src/backend/base/langflow/services/auth/service.py |  2 +-
 src/backend/tests/unit/helpers/test_flow.py        | 68 ++++++++++++++++++++++
 5 files changed, 97 insertions(+), 10 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git diff --check -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/  …(+60 more chars)`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/backend/base/langflow/api/v1/endpoints.py
 M src/backend/base/langflow/helpers/flow.py
 M src/backend/base/langflow/helpers/user.py
 M src/backend/base/langflow/services/auth/service.py
 M src/backend/tests/unit/helpers/test_flow.py

```
**Codex:** One docstring still mentioned the removed webhook `flow` parameter. I’m correcting that so the API documentation matches the new auth-first resolution flow.

**✎ files:** update `/work/src/backend/base/langflow/api/v1/endpoints.py`

**Codex:** The source diff is clean. Since dependency installation is blocked, I’m doing a lightweight line-length scan on the touched files and one more diff check that does not create build artifacts.

**→ shell:** `/bin/bash -lc "awk 'length("'$0) > 120 { print FILENAME ":" FNR ":" length($0) }'"' src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/he  …(+109 more chars)`
```
src/backend/base/langflow/api/v1/endpoints.py:197:136
src/backend/base/langflow/api/v1/endpoints.py:756:121
src/backend/base/langflow/api/v1/endpoints.py:890:137
src/backend/base/langflow/helpers/user.py:11:123

```
**→ shell:** `/bin/bash -lc 'git diff --check -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/  …(+60 more chars)`
**→ shell:** `/bin/bash -lc 'git diff -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/auth/ser  …(+52 more chars)`
```
diff --git a/src/backend/base/langflow/api/v1/endpoints.py b/src/backend/base/langflow/api/v1/endpoints.py
index 1781b0b..ed41d68 100644
--- a/src/backend/base/langflow/api/v1/endpoints.py
+++ b/src/backend/base/langflow/api/v1/endpoints.py
@@ -412,6 +412,22 @@ async def check_flow_user_permission(
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to run this flow")
 
 
+async def get_flow_by_id_or_endpoint_name_for_api_key(
+    flow_id_or_na  …(+9164 more chars)
```
**Codex:** The only new over-120-character line is the helper signature I changed; I’m wrapping it to match the project’s Ruff limit. Other reported long lines are pre-existing in the touched endpoint file.

**✎ files:** update `/work/src/backend/base/langflow/helpers/user.py`

**Codex:** The wrapping is done. I’m doing the last checks now: whitespace diff, status, and the focused test command result will remain noted as blocked by dependency download.

**→ shell:** `/bin/bash -lc 'git diff --check -- src/backend/base/langflow/api/v1/endpoints.py src/backend/base/langflow/helpers/flow.py src/backend/base/langflow/helpers/user.py src/backend/base/langflow/services/  …(+60 more chars)`
**→ shell:** `/bin/bash -lc "awk 'length("'$0) > 120 { print FILENAME ":" FNR ":" length($0) }'"' src/backend/base/langflow/helpers/user.py src/backend/tests/unit/helpers/test_flow.py"`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/backend/base/langflow/api/v1/endpoints.py
 M src/backend/base/langflow/helpers/flow.py
 M src/backend/base/langflow/helpers/user.py
 M src/backend/base/langflow/services/auth/service.py
 M src/backend/tests/unit/helpers/test_flow.py

```
**Codex:** Only the intended five files are modified, and whitespace/line-length checks on the new edits pass. I’m ready to summarize the remediation and the one verification blocker.

**Codex:** Implemented the authorization remediation.

Changed:
- Scoped `get_flow_by_id_or_endpoint_name(..., user_id=...)` for both UUID and endpoint-name lookups.
- Added owner-scoped flow dependencies for API-key and session run endpoints.
- Changed webhook execution to authenticate first, then resolve the flow scoped to that authenticated webhook user.
- Scoped webhook owner lookup in `AuthService`.
- Added regression tests for duplicate endpoint names across users and cross-user UUID rejection.

Verification:
- `git diff --check` passed.
- Python compile check passed before artifact cleanup.
- `uv run pytest src/backend/tests/unit/helpers/test_flow.py` could not run because `uv` failed downloading `cryptography==46.0.7` from PyPI due to a tunnel connection error.


---
*tokens — input 2057451 (cached 1880704), output 9712, reasoning 2929*
