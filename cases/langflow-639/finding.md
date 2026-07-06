# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Authorization Bypass Through User-Controlled Key — CWE-639
**Project:** `langflow-ai/langflow`
**Primary location:** `src/backend/base/langflow/api/v1/endpoints.py`
**Other files possibly involved:** `src/backend/base/langflow/helpers/flow.py`

## Details

## Summary

Insecure Direct Object Reference (IDOR) vulnerability in `/api/v1/responses` endpoint allows an authenticated attacker to execute any flow belonging to another user by specifying the victim's flow ID in the request.

## Details

The vulnerability exists in the `get_flow_by_id_or_endpoint_name` helper function in [`src/backend/base/langflow/helpers/flow.py` (lines 399-414)](https://github.com/langflow-ai/langflow/blob/v1.9.0/src/backend/base/langflow/helpers/flow.py#L399C1-L414C67).

When a flow is accessed via UUID (flow_id), the function queries the database directly without verifying if the authenticated user owns that flow:

```python
# src/backend/base/langflow/helpers/flow.py:399-414
async def get_flow_by_id_or_endpoint_name(flow_id_or_name: str, user_id: str | UUID | None = None) -> FlowRead:
    async with session_scope() as session:
        try:
            flow_id = UUID(flow_id_or_name)
            # When using UUID, query directly WITHOUT checking user_id
            flow = await session.get(Flow, flow_id)  # ❌ No user_id check!
        except ValueError:
            endpoint_name = flow_id_or_name
            stmt = select(Flow).where(Flow.endpoint_name == endpoint_name)
            # Only when using endpoint_name is user_id checked
            if user_id:
                stmt = stmt.where(Flow.user_id == uuid_user_id)
```

This function is used by the `/api/v1/responses` endpoint (defined in [`src/backend/base/langflow/api/v1/openai_responses.py:589`](https://github.com/langflow-ai/langflow/blob/v1.9.0/src/backend/base/langflow/api/v1/openai_responses.py#L589)).

## PoC (Proof of Concept)

```bash
# Attacker (user A) with API_KEY_A tries to execute victim (user B)'s flow
curl -X POST "http://localhost:7860/api/v1/responses" \
  -H "x-api-key: sk-ATTACKER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "VICTIM_FLOW_ID",
    "input_value": "test",
    "stream": false
  }'
# Returns 200 and executes the victim's flow
```

## Impact

Any authenticated user can:
1. Execute any flow in the system by knowing its flow ID
2. Access potentially sensitive data processed by victim's flows
3. Consume victim's resources
