# RootHideDebArchiver

RootHide Patcher never cleans up after itself, so
`<jbroot>/var/mobile/RootHidePatcher/` quietly becomes an archive of every deb it
has ever converted. This daemon makes that accident useful in two ways:

- **Serves the cache as a local Sileo repo** on `http://127.0.0.1:8140/`, so
  anything you have already converted reinstalls in a second — no Patcher UI, no
  converting the same package twice.
- **Mirrors new debs into iCloud Drive**, so the archive survives a
  re-jailbreak. The cache itself does not.

Reinstalling from the repo genuinely works because an already-converted deb is
not re-patched: installing rewrites 8 bytes of the `__TEXT` segname padding with
the live jbroot UUID and re-signs that slice. The archived debs are stored
unstamped, so they are not bound to the jbroot they were built under.

## Install

```sh
# From the repo this ships in:
#   https://guacforlife.github.io/repo/
```

Then **register the local repo with Sileo** — the package deliberately does not
edit your sources for you. Add `http://127.0.0.1:8140/` as a source in Sileo, or
append to `/var/jb/etc/apt/sources.list.d/sileo.sources`:

```
Types: deb
URIs: http://127.0.0.1:8140/
Suites: ./
Components:
```

## Commands

| | |
|---|---|
| `rhdarchived probe` | namespace, counts, and what it *would* copy |
| `rhdarchived once` | one-shot sync |
| `rhdarchived repo` | force an index rebuild |
| `notifyutil -p com.guacforlife.rhdarchived.sync` | kick the watcher |

Log: `/var/tmp/.rhdarchived.log`.

## Optional push notifications

Off unless configured — no token is compiled in. To get a banner when new debs
are archived, create `/var/jb/etc/rhdarchived.plist`:

```xml
<dict>
    <key>GotifyURL</key>   <string>http://your-gotify-host:8680</string>
    <key>GotifyToken</key> <string>your-app-token</string>
</dict>
```

## How it works, and why it is built this way

The device has **no `dpkg-scanpackages` (no perl), no python3 and no HTTP
server**, so both halves are in-daemon: control stanzas come from `dpkg-deb -f`
via `posix_spawn` (there is no `NSTask` on iOS — and the pipe must be drained
before `waitpid`, or it deadlocks), hashes from CommonCrypto in-process, and the
server is about 150 lines of BSD sockets. Results are cached by `(name, size)`,
which takes an index rebuild from ~155s cold to well under a second.

The watcher is a real kqueue (`dispatch_source` VNODE), with a 600s backstop poll
in case it ever goes quiet — silent loss would defeat the point of an archive.
The index is written to a **separate** directory from the one being watched, or
every rebuild would retrigger the watcher.

The daemon is entitled (`platform-application`, `MobileDocuments`) and runs in
the **real** filesystem namespace, while the cache it reads lives in the jbroot.
The jbroot prefix is therefore resolved at runtime via `dladdr()` and never
hardcoded, so a re-jailbreak needs no code change.

### Three things that will bite you if you reimplement this

1. **`com.apple.private.security.storage.MobileDocuments` is mandatory.** Without
   it iCloud Drive is `EPERM` even for root.
2. **iCloud placeholders.** An evicted file is present as `.<name>.icloud`, so the
   "already archived?" test must check both spellings — otherwise the daemon
   re-uploads the entire back catalogue every time the phone frees space.
3. **A `dispatch_source_t` in a local variable is released by ARC when its scope
   exits.** The daemon stays alive, logs "watching", and receives no events. The
   tell is that a manual `once` syncs fine while the watcher never fires.

### Serving an index to Sileo: cache validators are mandatory

Sileo fetches through `URLSession`, which applies **heuristic caching** to any
response with no `Last-Modified`, `ETag` or `Cache-Control` — so it can serve
itself a stale index indefinitely while `curl` and `apt-get update` both see the
fresh one. That split is the whole diagnosis. Index responses therefore carry
`Last-Modified` + `ETag` + `Cache-Control: no-cache, must-revalidate` and honour
`If-None-Match`; debs are `public, max-age=31536000`, since the filename pins
package and version.

Also: **APT asks a flat repo (`Suites: ./`) for `/./Packages`**. Exact-match
routing 404s that while `curl` works fine, because curl normalises the path
client-side and APT does not. Collapse `.` segments per component, and reject
`..` per component *after* percent-decoding rather than with a blanket
"contains ..", which would reject legitimate filenames. Test traversal with
`curl --path-as-is` — plain curl rewrites the URL and gives a false pass.

## Tested on

iOS 16.3.1, Dopamine / roothide, iPhone 14 Pro Max.
