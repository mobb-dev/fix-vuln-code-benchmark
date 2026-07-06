# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Information Exposure — CWE-200
**Project:** `AsyncHttpClient/async-http-client`
**Primary location:** `client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java`

## Details

## Summary

async-http-client leaks `Cookie` headers to cross-origin redirect targets. When following a redirect across a security boundary (different origin, or HTTPS→HTTP downgrade), the `propagatedHeaders()` method in `Redirect30xInterceptor.java` strips `Authorization` and `Proxy-Authorization` headers but does not strip `Cookie`, so session cookies and other sensitive cookie values are forwarded to the redirect target — which may be attacker-controlled.

## Details

The vulnerability is in `client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java`.

The caller computes `stripAuth` on each redirect:

```java
boolean sameBase    = request.getUri().isSameBase(newUri);
boolean stripAuth   = !sameBase || schemeDowngrade || stripAuthorizationOnRedirect;
// ...
requestBuilder.setHeaders(propagatedHeaders(request, realm, keepBody, stripAuth));
```

`stripAuth` is `true` whenever the redirect crosses an origin, downgrades the scheme, or the caller opted in via `AsyncHttpClientConfig#isStripAuthorizationOnRedirect()`.

In the vulnerable version, `propagatedHeaders()` only removes `Authorization` and `Proxy-Authorization` in that branch — `Cookie` is left untouched:

```java
private static HttpHeaders propagatedHeaders(Request request, Realm realm, boolean keepBody, boolean stripAuthorization) {
    HttpHeaders headers = request.getHeaders()
            .remove(HOST)
            .remove(CONTENT_LENGTH);

    if (!keepBody) {
        headers.remove(CONTENT_TYPE);
    }

    if (stripAuthorization || (realm != null && (realm.getScheme() == AuthScheme.NTLM
            || realm.getScheme() == AuthScheme.SCRAM_SHA_256))) {
        headers.remove(AUTHORIZATION)
                .remove(PROXY_AUTHORIZATION);
        // BUG: COOKIE is not removed here, so cookies leak across the security boundary.
    }
    return headers;
}
```

The companion test class `RedirectCredentialSecurityTest` covers `Authorization` / `Proxy-Authorization` stripping on cross-origin redirects and scheme downgrades, but has no coverage for `Cookie`, which is why the regression went unnoticed.

## Proof of concept

```java
import org.asynchttpclient.*;

AsyncHttpClient client = asyncHttpClient();

// trusted-api.com responds 302 -> https://evil.com
Request request = new RequestBuilder("GET")
        .setUrl("https://trusted-api.com/endpoint")
        .setHeader("Cookie", "session=abc123; csrf=xyz789; api_key=secret")
        .setHeader("Authorization", "Bearer token123")
        .build();

client.executeRequest(request).get();

// Request seen by evil.com after the redirect:
//   Authorization: <stripped>
//   Cookie:        session=abc123; csrf=xyz789; api_key=secret   <-- leaked
```

## Impact

- **Session hijacking** — leaked session cookies allow impersonation.
- **CSRF token theft** — CSRF tokens carried in cookies are disclosed.
- **API key theft** — API keys stored in cookies are disclosed.
- **Privacy** — tracking identifiers leak to third-party origins.

Realistic attack paths:

- Open-redirect in a trusted API endpoint.
- Compromised CDN or API gateway injecting redirects.
- MITM on a plaintext hop in the redirect chain.
