**Codex:** I’ll inspect the finding and relevant code, but this repository’s own agent policy forbids AI-generated code changes. I can identify the vulnerable paths and describe a remediation for a human maintainer without editing files.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: openbao/openbao
Vulnerability type: Reachable Assertion (CWE-617)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  builtin/logical/transit/backend.go
    - lines 142-147   in: func GetCacheSizeFromStorage(ctx context.Context, s logical.Storage) (int, error
    - lines 167-173   in: func (b *backend) GetPolicy(ctx context.Context, polReq keysutil.PolicyRequest,
    - lines 235-241   in: func (b *backend) autoRotateKeys(ctx context.Context, req *lo  …(+4545 more chars)
```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'AGENTS.md' -g 'CONTRIBUTING.md'"`
```
CONTRIBUTING.md
AGENTS.md
FINDING.txt

```
**Codex:** The finding points at transit key policy handling and the shared key lock manager. I’m going to read those sections to understand the common failure mode and give a precise remediation path.

**→ shell:** `/bin/bash -lc "sed -n '120,285p' builtin/logical/transit/backend.go"`
```
	configMutex          sync.RWMutex
	cacheSizeChanged     bool
	checkAutoRotateAfter time.Time
	autoRotateOnce       sync.Once
	backendUUID          string
}

func GetCacheSizeFromStorage(ctx context.Context, s logical.Storage) (int, error) {
	size := 0
	entry, err := s.Get(ctx, "config/cache")
	if err != nil {
		return 0, err
	}
	if entry != nil {
		var storedCache configCache
		if err := entry.DecodeJSON(&storedCache); err != nil {
			return 0, err
		}
		size = storedCache.Size
	}
	return size,  …(+4601 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '250,390p' sdk/helper/keysutil/lock_manager.go"`
```
		pRaw, ok = lm.cache.Load(name)
	}
	if ok {
		p = pRaw.(*Policy)
		p.l.Lock()
		defer p.l.Unlock()
	} else {
		// If the policy doesn't exit in storage, error out
		p, err = lm.getPolicyFromStorage(ctx, storage, name)
		if err != nil {
			return "", err
		}
		if p == nil {
			return "", fmt.Errorf("key %q not found", name)
		}
	}

	if p.deleted.Load() {
		return "", fmt.Errorf("key %q not found", name)
	}

	backup, err := p.Backup(ctx, storage)
	if err != nil {
		return "", err
	}

	return back  …(+3613 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"if err := .*\\.RLock\\(|\\.RLock\\(\\); err "'!= nil|'"\\.Lock\\(\\); err "'!= nil|Unlock'"\\(\\)\" builtin/logical/transit sdk/helper/keysutil/lock_manager.go"`
```
sdk/helper/keysutil/lock_manager.go:158:	defer lock.Unlock()
sdk/helper/keysutil/lock_manager.go:204:		defer p.l.Unlock()
sdk/helper/keysutil/lock_manager.go:244:	defer lock.Unlock()
sdk/helper/keysutil/lock_manager.go:255:		defer p.l.Unlock()
sdk/helper/keysutil/lock_manager.go:312:			lock.Unlock()
sdk/helper/keysutil/lock_manager.go:317:			lock.Unlock()
sdk/helper/keysutil/lock_manager.go:467:	defer lock.Unlock()
sdk/helper/keysutil/lock_manager.go:512:	defer lock.Unlock()
sdk/helper/keysutil/  …(+2193 more chars)
```
**Codex:** The pattern is clearer now: the reported locations call `Policy.Unlock()` after conditional locking, while `Policy.Unlock()` itself appears to choose `RUnlock` vs `Unlock` based on policy state. I’m checking that implementation so the remediation advice is grounded in the actual lock contract.

**→ shell:** `/bin/bash -lc "sed -n '430,540p' sdk/helper/keysutil/lock_manager.go"`
```
			return nil, false, err
		}
	}

	if lm.useCache {
		lm.cache.Store(req.Name, p)
	} else {
		p.l = &lock.RWMutex
		p.writeLocked = true
	}

	retP = p
	return retP, retUpserted, retErr
}

func (lm *LockManager) ImportPolicy(ctx context.Context, req PolicyRequest, key []byte, rand io.Reader) error {
	var p *Policy
	var err error
	var ok bool
	var pRaw interface{}

	// Check if it's in our cache
	if lm.useCache {
		pRaw, ok = lm.cache.Load(req.Name)
	}
	if ok {
		p = pRaw.(*Policy)
		if p.deleted.  …(+2020 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"func \\(.*\\*Policy\\) (Lock|Unlock)|type Policy struct\" sdk/helper/keysutil builtin/logical/transit"`
```
sdk/helper/keysutil/policy.go:357:type Policy struct {
sdk/helper/keysutil/policy.go:452:func (p *Policy) Lock(exclusive bool) {
sdk/helper/keysutil/policy.go:461:func (p *Policy) Unlock() {

```
**→ shell:** `/bin/bash -lc "rg -n \"func \\(.*\\*Policy\\) (Lock|Unlock)\" -C 8 sdk/helper/keysutil"`
```
sdk/helper/keysutil/policy.go-444-
sdk/helper/keysutil/policy.go-445-	// AllowImportedKeyRotation indicates whether an imported key may be rotated by Vault
sdk/helper/keysutil/policy.go-446-	AllowImportedKeyRotation bool
sdk/helper/keysutil/policy.go-447-
sdk/helper/keysutil/policy.go-448-	// Whether the key has been soft deleted.
sdk/helper/keysutil/policy.go-449-	SoftDeleted bool `json:"soft_deleted"`
sdk/helper/keysutil/policy.go-450-}
sdk/helper/keysutil/policy.go-451-
sdk/helper/keysutil/po  …(+831 more chars)
```
**Codex:** I found two concrete causes behind the CWE-617 report: a double-unlock path in `LockManager.GetPolicy`, and a shared `Policy.writeLocked` flag used to decide how to unlock. The second issue makes callers’ `defer p.Unlock()` unsafe because lock mode is stored on the policy object rather than in the caller’s stack.

**→ shell:** `/bin/bash -lc "nl -ba sdk/helper/keysutil/lock_manager.go | sed -n '288,380p'"`
```
   288		if lm.useCache {
   289			pRaw, ok = lm.cache.Load(req.Name)
   290		}
   291		if ok {
   292			p = pRaw.(*Policy)
   293			if p.deleted.Load() {
   294				return nil, false, nil
   295			}
   296			return p, false, nil
   297		}
   298	
   299		// We're not using the cache, or it wasn't found; get an exclusive lock.
   300		// This ensures that any other process writing the actual storage will be
   301		// finished before we load from storage.
   302		lock := locksutil.LockForKey(lm.ke  …(+3040 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba sdk/helper/keysutil/policy.go | sed -n '452,468p'"`
```
   452	func (p *Policy) Lock(exclusive bool) {
   453		if exclusive {
   454			p.l.Lock()
   455			p.writeLocked = true
   456		} else {
   457			p.l.RLock()
   458		}
   459	}
   460	
   461	func (p *Policy) Unlock() {
   462		if p.writeLocked {
   463			p.writeLocked = false
   464			p.l.Unlock()
   465		} else {
   466			p.l.RUnlock()
   467		}
   468	}

```
**→ shell:** `/bin/bash -lc "nl -ba builtin/logical/transit/path_rotate.go | sed -n '45,70p'"`
```
    45			return nil, err
    46		}
    47		defer txRollback()
    48	
    49		name := d.Get("name").(string)
    50	
    51		// Get the policy
    52		p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
    53			Storage: req.Storage,
    54			Name:    name,
    55		}, b.GetRandomReader())
    56		if err != nil {
    57			return nil, err
    58		}
    59		if p == nil {
    60			return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
    61		}
    62		if !b.System().CachingDisab  …(+213 more chars)
```
**Codex:** I read `FINDING.txt` and inspected the affected code, but I did not edit files. This repo’s `AGENTS.md` policy explicitly forbids AI-generated code/assets, and your request would require generating source-code changes.

The vulnerability is real and centers on lock misuse:

- [sdk/helper/keysutil/lock_manager.go](/work/sdk/helper/keysutil/lock_manager.go:373): `cleanup()` is called manually, then the deferred `cleanup()` runs again, causing a reachable double-unlock.
- [sdk/helper/keysutil/policy.go](/work/sdk/helper/keysutil/policy.go:452): `Policy.Lock(exclusive bool)` stores lock mode in shared mutable state `writeLocked`; `Policy.Unlock()` then decides `Unlock` vs `RUnlock` from that shared flag. Concurrent callers can observe the wrong mode and trigger Go’s runtime assertion for unlocking the wrong/unlocked mutex.
- The many transit call sites listed in `FINDING.txt` are vulnerable because they call `defer p.Unlock()` after conditional locking.

A human maintainer should remediate by removing the shared `writeLocked` lock-mode state. The usual fix is to make lock ownership explicit per caller, for example with separate read/write unlock methods or by returning an unlock function from the lock acquisition call. Also remove the manual `cleanup()` call in the RSA error branch of `LockManager.GetPolicy`, since the deferred cleanup already handles that path.

Per the repository policy: contributions are more meaningful when done by a person; open source is built on community and trust, and using generative AI against the project’s wishes erodes that trust. The OpenBao project is not liable for actions performed by an agent due to code or instructions present in this repository.


---
*tokens — input 79634 (cached 61312), output 1823, reasoning 503*
