**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: langflow-ai/langflow
2	Vulnerability type: Authorization Bypass Through User-Controlled Key (CWE-639)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  src/backend/base/langflow/api/v1/endpoints.py
7	    - lines 412-417   in: async def check_flow_user_permission(
8	    - lines 556-562   in:  …(+300 more chars)
**→ Read**(file_path=/work/AGENTS.md)
  ↳ *result:* 1	# AGENTS.md
2	
3	This file provides guidance to AI coding agents when working with code in this repository.
4	
5	## Project Overview
6	
7	Langflow is a visual workflow builder for AI-powered agents. It has a Python/FastAPI backend, React/TypeScript frontend, and a lightweight executor CLI (lfx).
8	
9	## Prerequisites
10	
11	- **Python:** 3.10-3.1  …(+6808 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/api/v1/endpoints.py, offset=380, limit=300)
  ↳ *result:* 380	    try:
381	        result = await simple_run_flow(
382	            flow=flow,
383	            input_request=input_request,
384	            stream=True,
385	            api_key_user=api_key_user,
386	            event_manager=event_manager,
387	            context=context,
388	        )
389	        event_manager.on_end(data={"result": result.m  …(+13439 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/helpers/flow.py, offset=380, limit=40)
  ↳ *result:* 380	    return create_model(name, **fields)
381	
382	
383	def get_arg_names(inputs: list[Vertex]) -> list[dict[str, str]]:
384	    """Returns a list of dictionaries containing the component name and its corresponding argument name.
385	
386	    Args:
387	        inputs (List[Vertex]): A list of Vertex objects representing the inputs.
388	
389	    R  …(+1402 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/api/v1/endpoints.py, offset=680, limit=220)
  ↳ *result:* 680	
681	@router.get("/webhook-events/{flow_id_or_name}", include_in_schema=False)
682	async def webhook_events_stream(
683	    flow_id_or_name: str,  # noqa: ARG001 - Used by get_flow_by_id_or_endpoint_name dependency
684	    flow: Annotated[Flow, Depends(get_flow_by_id_or_endpoint_name)],
685	    user: Annotated[User | UserRead, Depends(get_curre  …(+9507 more chars)
**→ Bash**(command=grep -rn "get_flow_by_id_or_endpoint_name\|get_webhook_user\|check_flow_user_permission" src/backend/base/langflow/ src/lfx 2>/dev/null)
  ↳ *result:* src/backend/base/langflow/tests/api/v1/test_openai_responses_error.py:48:        patch("langflow.api.v1.openai_responses.get_flow_by_id_or_endpoint_name") as mock_get_flow,
src/backend/base/langflow/agentic/utils/flow_component.py:9:from langflow.helpers.flow import get_flow_by_id_or_endpoint_name
src/backend/base/langflow/agentic/utils/flow_compon  …(+3962 more chars)
**→ Bash**(command=git log --oneline -5 && wc -l src/backend/base/langflow/api/v1/endpoints.py)
  ↳ *result:* 651b1de baseline
1200 src/backend/base/langflow/api/v1/endpoints.py
**→ Read**(file_path=/work/src/backend/base/langflow/services/auth/service.py, offset=380, limit=70)
  ↳ *result:* 380	    ) -> User | UserRead:
381	        """Delegates to authenticate_with_credentials()."""
382	        return await self.authenticate_with_credentials(token, api_key, db)
383	
384	    async def get_current_active_user(self, current_user: User | UserRead) -> User | UserRead | None:
385	        if not current_user.is_active:
386	            return  …(+3020 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/api/v2/workflow.py, offset=140, limit=60)
  ↳ *result:* 140	            - 403: Developer API disabled
141	            - 404: Flow not found or user lacks access
142	            - 500: Invalid flow data or validation error
143	            - 501: Streaming or background mode not yet implemented
144	            - 503: Database unavailable
145	            - 504: Execution timeout exceeded
146	    """
147	    …(+2190 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/api/v1/endpoints.py, offset=1, limit=70)
  ↳ *result:* 1	from __future__ import annotations
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
13	from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPE  …(+2723 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/api/v1/openai_responses.py, offset=620, limit=40)
  ↳ *result:* 620	
621	    await logger.adebug(f"All headers received: {list(http_request.headers.keys())}")
622	    await logger.adebug(f"Extracted global variables from headers: {list(variables.keys())}")
623	
624	    # Validate tools parameter - error out if tools are provided
625	    if request.tools is not None:
626	        error_response = create_openai_er  …(+1231 more chars)
**→ Bash**(command=grep -rn "permission to run this flow\|do not have permission\|user_id=" src/backend/base/langflow/tests/ src/backend/tests/ 2>/dev/null | h  …(+7 more chars))
  ↳ *result:* src/backend/base/langflow/tests/api/v1/test_deployment_guard_delete_endpoints.py:190:    fake_flow = SimpleNamespace(id=flow_id, user_id=user_id)
src/backend/base/langflow/tests/api/v1/test_deployment_guard_delete_endpoints.py:239:        user_id=user_id,
src/backend/base/langflow/tests/services/database/models/flow_version_deployment_attachment/te  …(+6068 more chars)
**→ Bash**(command=grep -rln "check_flow_user_permission\|run this flow\|simplified_run\|/run/\|webhook_run\|get_flow_by_id_or_endpoint_name" src/backend/base/  …(+53 more chars))
  ↳ *result:* src/backend/base/langflow/tests/api/v1/test_openai_responses_error.py
src/backend/tests/unit/test_webhook.py
src/backend/tests/unit/test_endpoints.py
src/backend/tests/unit/agentic/utils/test_flow_component.py
src/backend/tests/unit/agentic/utils/test_flow_graph.py
src/backend/tests/unit/components/flow_controls/test_loop.py
src/backend/tests/unit/  …(+169 more chars)
**→ Bash**(command=grep -n "check_flow_user_permission\|403\|permission\|other_user\|different.*user\|user_id" src/backend/tests/unit/test_endpoints.py | head   …(+3 more chars))
  ↳ *result:* 719:async def test_user_cannot_run_other_users_flow(client: AsyncClient, simple_api_test, user_two_api_key):
720:    """Test that a user cannot run another user's flow - should return 403 Forbidden."""
727:    assert response.status_code == status.HTTP_403_FORBIDDEN, response.text
728:    assert "You do not have permission to run this flow" in resp  …(+1580 more chars)
**→ Read**(file_path=/work/src/backend/tests/unit/test_endpoints.py, offset=715, limit=150)
  ↳ *result:* 715	    assert "outputs" in json_response
716	
717	
718	@pytest.mark.benchmark
719	async def test_user_cannot_run_other_users_flow(client: AsyncClient, simple_api_test, user_two_api_key):
720	    """Test that a user cannot run another user's flow - should return 403 Forbidden."""
721	    # simple_api_test belongs to active_user, but we're using use  …(+6209 more chars)
**→ Read**(file_path=/work/src/backend/base/langflow/agentic/utils/flow_component.py, offset=30, limit=25)
  ↳ *result:* 30	        - display_name: Display name of the component
31	        - description: Component description
32	        - template: Full template configuration with all fields
33	        - outputs: List of output definitions
34	        - inputs: List of input definitions
35	        - flow_id: The parent flow ID
36	        - flow_name: The parent flow n  …(+627 more chars)
**→ Bash**(command=grep -rn "get_flow_by_id_or_endpoint_name\|user_id\|other_user\|404\|403\|not found\|permission" src/backend/tests/unit/api/v2/test_workflow  …(+14 more chars))
  ↳ *result:* src/backend/tests/unit/api/v2/test_workflow.py:78:        assert response.status_code == 403
src/backend/tests/unit/api/v2/test_workflow.py:99:        assert response.status_code == 403
src/backend/tests/unit/api/v2/test_workflow.py:120:        """Test POST workflow execution is allowed when developer API is enabled - flow not found."""
src/backend  …(+2971 more chars)
**Claude:** The tests confirm the picture: v1 run endpoints are already guarded by `check_flow_user_permission` (cross-user UUID access → 403, as asserted in `test_endpoints.py`). The genuine, unguarded bypass is in the shared resolver `get_flow_by_id_or_endpoint_name`, which is *expected* by its callers (`v2/workflow.py`, `openai_responses.py`, agentic utils — all pass the authenticated `user_id`) to enforce ownership, but only does so for the endpoint-name branch and ignores `user_id` entirely on the UUID branch. That's the CWE-639 root cause.

Let me confirm the resolver's imports before editing.

**→ Bash**(command=grep -n "^from\|^import\|session_scope\|from sqlmodel\|HTTPException\|from uuid" src/backend/base/langflow/helpers/flow.py | head -40)
  ↳ *result:* 1:from __future__ import annotations
3:from typing import TYPE_CHECKING, Any, cast
4:from uuid import UUID
6:from fastapi import HTTPException
7:from lfx.log.logger import logger
8:from pydantic.v1 import BaseModel, Field, create_model
9:from sqlalchemy.orm import aliased
10:from sqlmodel import asc, desc, select
12:from langflow.schema.schema impo  …(+692 more chars)
**Claude:** All imports present. Applying the resolver fix:

**→ Edit**(replace_all=false, file_path=/work/src/backend/base/langflow/helpers/flow.py, old_string=    async with session_scope() as session:
        endpoint_name = None
        try:
            flow_id = UUID(flow_id_or_name)
             …(+439 more chars), new_string=    async with session_scope() as session:
        # Scope the lookup to the requesting user so a flow can only be resolved by its
        #  …(+880 more chars))
  ↳ *result:* The file /work/src/backend/base/langflow/helpers/flow.py has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Let me verify the final state of the function:

**→ Read**(file_path=/work/src/backend/base/langflow/helpers/flow.py, offset=399, limit=25)
  ↳ *result:* 399	async def get_flow_by_id_or_endpoint_name(flow_id_or_name: str, user_id: str | UUID | None = None) -> FlowRead:
400	    async with session_scope() as session:
401	        # Scope the lookup to the requesting user so a flow can only be resolved by its
402	        # owner. Without this, the user-controlled flow id/name is the sole authorization
4  …(+1054 more chars)
**Claude:** Let me verify the file compiles and run the relevant authorization tests.

**→ Bash**(command=python -m py_compile src/backend/base/langflow/helpers/flow.py && echo "compile OK")
  ↳ *result:* compile OK
**→ Bash**(command=timeout 540 uv run pytest src/backend/tests/unit/api/v2/test_workflow.py -k "not_found or permission or 403 or 404" -q 2>&1 | tail -30)
  ↳ *result:* Using CPython 3.11.15 interpreter at: /usr/local/bin/python3
Creating virtual environment at: .venv
   Building langflow-base @ file:///work/src/backend/base
   Building lfx @ file:///work/src/lfx
   Building langflow-sdk @ file:///work/src/sdk
   Building langflow @ file:///work
  × Failed to download `chromadb==1.5.7`
  ├─▶ Request failed after 3  …(+657 more chars)
**Claude:** The test suite can't run — the sandbox has no network access to install dependencies (`chromadb` download fails). The change itself compiles cleanly. Let me do a final verification that no caller relies on cross-user access while passing a `user_id` (which would now break), by reviewing the callers' user_id sources.

**→ Bash**(command=grep -n "get_flow_by_id_or_endpoint_name(" src/backend/base/langflow/api/v2/workflow.py src/backend/base/langflow/api/v1/openai_responses.py  …(+112 more chars))
  ↳ *result:* src/backend/base/langflow/agentic/utils/flow_graph.py:43:        flow: FlowRead | None = await get_flow_by_id_or_endpoint_name(flow_id_or_name, user_id)
src/backend/base/langflow/agentic/utils/flow_graph.py:174:        flow: FlowRead | None = await get_flow_by_id_or_endpoint_name(flow_id_or_name, user_id)
src/backend/base/langflow/agentic/utils/flo  …(+947 more chars)
**Claude:** All callers pass the *authenticated* user's id (`api_key_user.id` / a `user_id` derived from the acting user), and the v1 `Depends()` usages pass `None`. The fix is complete and consistent. Here's a summary.

## What the vulnerability was

**CWE-639: Authorization Bypass Through User-Controlled Key**, rooted in `get_flow_by_id_or_endpoint_name` (`src/backend/base/langflow/helpers/flow.py`).

The resolver accepts a `user_id` so callers can scope a flow lookup to its owner — but it only applied that filter on the **endpoint-name** branch. The **UUID** branch (`session.get(Flow, flow_id)`) ignored `user_id` entirely. So the user-controlled flow id was the *only* key used to fetch the flow, with no ownership binding.

Callers that rely on the resolver to enforce ownership were therefore bypassable:
- `api/v2/workflow.py` (`execute_workflow`, line 151; another at 580) — comment literally says *"Validate flow exists and user has permission"*, but no separate check existed.
- `api/v1/openai_responses.py` (line 635) — passes the user id, treats a miss as "not found", no separate check.
- `agentic/utils/flow_component.py` / `flow_graph.py`.

A holder of any valid API key could run/read another user's flow by its UUID through these paths.

(The v1 `/run` endpoints flagged in `FINDING.txt` consume the same resolver but were additionally guarded by `check_flow_user_permission`, which is why `test_endpoints.py` asserts a 403 there — that behavior is preserved.)

## The fix

In `get_flow_by_id_or_endpoint_name`, the `user_id` filter is now applied uniformly to **both** the UUID and endpoint-name lookups. When `user_id` is supplied, a flow owned by a different user is no longer returned (the query yields nothing → existing 404 path).

## Behavior preserved
- **Owner access** — flow found, unchanged.
- **v1 `/run` endpoints** — still call the resolver with `user_id=None`, so resolution is unscoped and `check_flow_user_permission` continues to return **403** for cross-user access (matching existing tests).
- **v2 / openai / agentic** — already pass the authenticated user's id; legitimate own-flow calls still succeed, cross-user calls now correctly return 404 / "not found" (the structured `FLOW_NOT_FOUND` and OpenAI "flow not found" responses those endpoints already produce on a miss).

No test could be executed because the sandbox has no network access to install dependencies (`chromadb` download fails); the edited file byte-compiles cleanly. No commits or other changes were made.


---
**Final (success):** All callers pass the *authenticated* user's id (`api_key_user.id` / a `user_id` derived from the acting user), and the v1 `Depends()` usages pass `None`. The fix is complete and consistent. Here's a summary.

## What the vulnerability was

**CWE-639: Authorization Bypass Through User-Controlled Key**, rooted in `get_flow_by_id_or_endpoint_name` (`src/backend/base/langflow/helpers/flow.py`).

The resolver accepts a `user_id` so callers can scope a flow lookup to its owner — but it only applied that filter on the **endpoint-name** branch. The **UUID** branch (`session.get(Flow, flow_id)`) ignored `user_id` entirely. So the user-controlled flow id was the *only* key used to fetch the flow, with no ownership binding.

Callers that rely on the resolver to enforce ownership were therefore bypassable:
- `api/v2/workflow.py` (`execute_workflow`, line 151; another at 580) — comment literally says *"Validate flow exists and user has permission"*, but no separate check existed.
- `api/v1/openai_responses.py` (line 635) — passes the user id, treats a miss as "not found", no separate check.
- `agentic/utils/flow_component.py` / `flow_graph.py`.

A holder of any valid API key could run/read another user's flow by its UUID through these paths.

(The v1 `/run` endpoints flagged in `FINDING.txt` consume the same resolver but were additionally guarded by `check_flow_user_permission`, which is why `test_endpoints.py` asserts a 403 there — that behavior is preserved.)

## The fix

In `get_flow_by_id_or_endpoint_name`, the `user_id` filter is now applied uniformly to **both** the UUID and endpoint-name lookups. When `user_id` is supplied, a flow owned by a different user is no longer returned (the query yields nothing → existing 404 path).

## Behavior preserved
- **Owner access** — flow found, unchanged.
- **v1 `/run` endpoints** — still call the resolver with `user_id=None`, so resolution is unscoped and `check_flow_user_permission` continues to return **403** for cross-user access (matching existing tests).
- **v2 / openai / agentic** — already pass the authenticated user's id; legitimate own-flow calls still succeed, cross-user calls now correctly return 404 / "not found" (the structured `FLOW_NOT_FOUND` and OpenAI "flow not found" responses those endpoints already produce on a miss).

No test could be executed because the sandbox has no network access to install dependencies (`chromadb` download fails); the edited file byte-compiles cleanly. No commits or other changes were made.

*turns 24 · cost $1.905*
