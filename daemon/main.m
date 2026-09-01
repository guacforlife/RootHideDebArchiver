// rhdarchived — mirrors the RootHide Patcher's deb cache into iCloud Drive,
// on the phone, with no Mac involved.
//
// The Patcher never cleans its working directory, so <jbroot>/var/mobile/
// RootHidePatcher accumulates every deb it has ever converted. That cache does
// not survive a re-jailbreak (new jbroot), which is exactly why it is worth
// mirroring somewhere durable.
//
// Two namespaces are in play and they are easy to confuse:
//   * the SOURCE lives in the jbroot, which this daemon does NOT see as "/" —
//     LaunchDaemons run in the real filesystem namespace, so the jbroot has to
//     be resolved at runtime via dladdr(). Never hardcode the UUID; it changes
//     on every re-jailbreak.
//   * the DESTINATION, /var/mobile/Library/Mobile Documents, is a real-namespace
//     path this daemon sees directly — but it is sandbox-protected, denied even
//     to root. Reaching it needs com.apple.private.security.storage.MobileDocuments,
//     which is why this binary ships entitlements (see ents.plist) and must be
//     installed through the RootHide Patcher, which preserves and trustcaches them.
//
// Watching is a real kqueue on the source directory (dispatch VNODE source), not
// a poll — the whole point of moving this on-device.

#import <Foundation/Foundation.h>
#import "repo.h"
#include <dlfcn.h>
#include <sys/stat.h>
#include <notify.h>

#define LOG_FILE @"/var/tmp/.rhdarchived.log"
#define DEST_REL @"Library/Mobile Documents/com~apple~CloudDocs/Jailbreak/roothide-deb-cache"
#define NOTIFY_SYNC "com.guacforlife.rhdarchived.sync"
#define REPO_PORT 8140

// Optional Gotify push, off unless you configure it. Create
// <jbroot>/etc/rhdarchived.plist with GotifyURL and GotifyToken to get a banner
// when new debs are archived; without it the daemon simply does not notify.
// Deliberately NOT compiled in — a push token does not belong in source.
// Jbroot-relative, resolved like SourceDir(): this runs in the REAL namespace
// where /var/jb does not resolve, so a literal /var/jb path would silently
// never be found.
#define CONFIG_REL @"etc/rhdarchived.plist"

static void RHDLog(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                      [[NSISO8601DateFormatter new] stringFromDate:[NSDate date]], msg];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:LOG_FILE];
    if (!fh) {
        [line writeToFile:LOG_FILE atomically:NO encoding:NSUTF8StringEncoding error:nil];
        chmod([LOG_FILE UTF8String], 0644);
    } else {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

// The jbroot is the ".jbroot-<UUID>" component of our own module path. dladdr on
// a local function is the documented way to get that path from inside the real
// namespace, where /var/jb does not resolve.
static NSString *JBRoot(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    Dl_info info = {0};
    if (dladdr((const void *)&JBRoot, &info) == 0 || !info.dli_fname) return nil;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    for (NSString *comp in [path pathComponents]) {
        if ([comp hasPrefix:@".jbroot-"]) {
            NSRange r = [path rangeOfString:comp];
            cached = [path substringToIndex:r.location + r.length];
            return cached;
        }
    }
    return nil;
}

static NSString *SourceDir(void) {
    NSString *jb = JBRoot();
    return jb ? [jb stringByAppendingPathComponent:@"var/mobile/RootHidePatcher"] : nil;
}

static NSString *DestDir(void) {
    return [@"/var/mobile" stringByAppendingPathComponent:DEST_REL];
}

// A file that iCloud has evicted is not gone — it is present as a ".<name>.icloud"
// placeholder. Treating that as "missing" would re-upload the entire back
// catalogue every time the phone frees up space, so both spellings count.
static BOOL DestHasFile(NSString *dir, NSString *name) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:[dir stringByAppendingPathComponent:name]]) return YES;
    NSString *ph = [NSString stringWithFormat:@".%@.icloud", name];
    return [fm fileExistsAtPath:[dir stringByAppendingPathComponent:ph]];
}

static BOOL EnsureDir(NSString *path) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:path isDirectory:&isDir]) return isDir;
    NSError *err = nil;
    if (![fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&err]) {
        RHDLog(@"mkdir failed %@: %@", path, err.localizedDescription);
        return NO;
    }
    // Written by root, but it is the mobile user's iCloud container — hand it
    // back or the file provider treats it as foreign.
    chown([path UTF8String], 501, 501);
    return YES;
}

static NSDictionary *RHDConfig(void) {
    static NSDictionary *cfg = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *jb = JBRoot();
        NSString *path = jb ? [jb stringByAppendingPathComponent:CONFIG_REL] : nil;
        cfg = (path ? [NSDictionary dictionaryWithContentsOfFile:path] : nil) ?: @{};
    });
    return cfg;
}

static void Notify(NSString *title, NSString *message) {
    NSString *base  = RHDConfig()[@"GotifyURL"];
    NSString *token = RHDConfig()[@"GotifyToken"];
    if (base.length == 0 || token.length == 0) return;   // not configured: no push

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/message?token=%@",
                                       base, token]];
    if (!url) { RHDLog(@"notify skipped: bad GotifyURL"); return; }
    NSDictionary *body = @{@"title": title, @"message": message, @"priority": @4,
                           @"extras": @{@"client::display": @{@"contentType": @"text/markdown"}}};
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    req.timeoutInterval = 15;
    // A self-hosted Gotify is usually LAN-only, so this fails whenever the phone
    // is away from home. The archive copy has already happened by then; the
    // banner is not worth queueing or retrying for.
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            if (e) RHDLog(@"notify failed: %@", e.localizedDescription);
            dispatch_semaphore_signal(sem);
        }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
}

// Copies *.deb from one directory to another, newest first, skipping anything
// already there. Returns the names it copied.
static NSArray<NSString *> *SyncDir(NSString *src, NSString *dst) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *copied = [NSMutableArray array];
    NSArray *names = [fm contentsOfDirectoryAtPath:src error:nil];
    if (!names) return copied;
    if (!EnsureDir(dst)) return copied;

    for (NSString *name in [names sortedArrayUsingSelector:@selector(compare:)]) {
        if (![[name pathExtension] isEqualToString:@"deb"]) continue;
        if (DestHasFile(dst, name)) continue;

        NSString *from = [src stringByAppendingPathComponent:name];
        NSString *to = [dst stringByAppendingPathComponent:name];
        // Copy to a temp name first: a half-written file in the container would
        // be picked up and uploaded truncated.
        NSString *tmp = [dst stringByAppendingPathComponent:
                         [NSString stringWithFormat:@".%@.partial", name]];
        [fm removeItemAtPath:tmp error:nil];

        NSError *err = nil;
        if (![fm copyItemAtPath:from toPath:tmp error:&err]) {
            RHDLog(@"copy failed %@: %@", name, err.localizedDescription);
            [fm removeItemAtPath:tmp error:nil];
            continue;
        }
        chown([tmp UTF8String], 501, 501);
        chmod([tmp UTF8String], 0644);
        if (![fm moveItemAtPath:tmp toPath:to error:&err]) {
            RHDLog(@"rename failed %@: %@", name, err.localizedDescription);
            [fm removeItemAtPath:tmp error:nil];
            continue;
        }
        [copied addObject:name];
    }
    return copied;
}

static void RunSync(void) {
    NSString *src = SourceDir();
    if (!src) { RHDLog(@"cannot resolve jbroot, skipping"); return; }
    NSString *dst = DestDir();

    NSArray *patched = SyncDir(src, dst);
    NSArray *inbox = SyncDir([src stringByAppendingPathComponent:@".Inbox"],
                             [dst stringByAppendingPathComponent:@"_inbox-originals"]);

    // Refresh the Sileo index off the same event. Only the patched cache is
    // published — .Inbox holds rootful/incompatible originals that would be
    // wrong to offer for install. No-ops when the deb set is unchanged.
    RHDRepoRefresh();

    NSUInteger total = patched.count + inbox.count;
    if (total == 0) return;
    RHDLog(@"archived %lu patched + %lu inbox", (unsigned long)patched.count, (unsigned long)inbox.count);

    NSMutableArray *all = [NSMutableArray arrayWithArray:patched];
    [all addObjectsFromArray:inbox];
    NSMutableString *msg = [NSMutableString stringWithFormat:@"**%lu new** in the RootHide cache",
                            (unsigned long)total];
    if (inbox.count) [msg appendFormat:@" (%lu patched, %lu unpatched)",
                      (unsigned long)patched.count, (unsigned long)inbox.count];
    [msg appendString:@"\n\n"];
    // A first run copies the whole back catalogue; don't push 140 filenames to a
    // lock-screen banner.
    NSUInteger shown = MIN(total, (NSUInteger)10);
    for (NSUInteger i = 0; i < shown; i++) [msg appendFormat:@"- %@\n", all[i]];
    if (total > shown) [msg appendFormat:@"- …and %lu more\n", (unsigned long)(total - shown)];
    Notify(@"RootHide deb cache", msg);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *cmd = argc > 1 ? [NSString stringWithUTF8String:argv[1]] : nil;
        if (JBRoot())
            RHDRepoConfigure([JBRoot() stringByAppendingPathComponent:@"var/mobile/RootHideRepo"],
                             SourceDir(), JBRoot());

        // `rhdarchived probe` — one-shot diagnostics, run by hand over SSH. Kept
        // in the shipping binary because the two namespaces make "which path am
        // I actually looking at" the first question of every future problem.
        if ([cmd isEqualToString:@"probe"]) {
            NSFileManager *fm = [NSFileManager defaultManager];
            printf("jbroot   : %s\n", JBRoot().UTF8String ?: "(unresolved)");
            printf("source   : %s\n", SourceDir().UTF8String ?: "(none)");
            NSArray *s = [fm contentsOfDirectoryAtPath:SourceDir() error:nil];
            printf("source n : %lu entries\n", (unsigned long)s.count);
            NSString *dst = DestDir();
            printf("dest     : %s\n", dst.UTF8String);
            NSError *err = nil;
            NSArray *d = [fm contentsOfDirectoryAtPath:[dst stringByDeletingLastPathComponent]
                                                 error:&err];
            printf("dest parent: %s\n", err ? err.localizedDescription.UTF8String
                                            : [NSString stringWithFormat:@"%lu entries",
                                               (unsigned long)d.count].UTF8String);
            BOOL ok = EnsureDir(dst);
            printf("mkdir dest : %s\n", ok ? "OK" : "FAILED");
            if (ok) {
                // How many of the archive's files this phone can already see
                // matters more than it looks: if the container listing has not
                // been populated, a sync would treat every file as new and
                // re-upload the whole back catalogue.
                NSArray *have = [fm contentsOfDirectoryAtPath:dst error:nil];
                NSUInteger real = 0, placeholder = 0;
                for (NSString *n in have) {
                    if ([n hasSuffix:@".icloud"]) placeholder++;
                    else if ([[n pathExtension] isEqualToString:@"deb"]) real++;
                }
                printf("dest       : %lu materialised, %lu placeholders\n",
                       (unsigned long)real, (unsigned long)placeholder);
                NSUInteger pending = 0;
                for (NSString *n in [fm contentsOfDirectoryAtPath:SourceDir() error:nil])
                    if ([[n pathExtension] isEqualToString:@"deb"] && !DestHasFile(dst, n)) pending++;
                printf("would copy : %lu\n", (unsigned long)pending);
            }
            return ok ? 0 : 1;
        }

        if ([cmd isEqualToString:@"once"]) { RunSync(); return 0; }

        // `rhdarchived repo` — rebuild the Sileo index by hand, e.g. after
        // deleting debs from the cache directly.
        if ([cmd isEqualToString:@"repo"]) {
            NSString *pkgs = [[JBRoot() stringByAppendingPathComponent:@"var/mobile/RootHideRepo"]
                              stringByAppendingPathComponent:@"Packages"];
            // Force a real rebuild: a refresh short-circuits when the package
            // list is byte-identical, which is right on the sync path but makes
            // a manual "rebuild" do nothing. The content cache keeps it fast.
            [[NSFileManager defaultManager] removeItemAtPath:pkgs error:nil];
            RHDRepoRefresh();
            NSString *s = [NSString stringWithContentsOfFile:pkgs encoding:NSUTF8StringEncoding error:nil];
            NSUInteger n = 0;
            for (NSString *l in [s componentsSeparatedByString:@"\n"])
                if ([l hasPrefix:@"Package: "]) n++;
            printf("repo: %s\n", pkgs.UTF8String);
            printf("packages: %lu\n", (unsigned long)n);
            printf("add in Sileo: http://127.0.0.1:%d/\n", REPO_PORT);
            return 0;
        }

        RHDLog(@"starting (jbroot=%@)", JBRoot() ?: @"?");
        RunSync();
        RHDRepoServe(REPO_PORT);

        dispatch_queue_t q = dispatch_queue_create("com.guacforlife.rhdarchived", DISPATCH_QUEUE_SERIAL);

        NSString *src = SourceDir();
        int fd = src ? open([src fileSystemRepresentation], O_EVTONLY) : -1;
        if (fd < 0) {
            RHDLog(@"cannot open source for watching: %s", strerror(errno));
        } else {
            // Static, not a local: under ARC a dispatch source is an ObjC object,
            // so a local one is released the moment its scope exits and the
            // watch silently stops. Cost me a debug cycle — the daemon stayed
            // alive and logged "watching", but no event ever arrived.
            static dispatch_source_t sVnode;
            sVnode = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd,
                DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_RENAME
                | DISPATCH_VNODE_DELETE, q);
            dispatch_source_set_event_handler(sVnode, ^{
                RHDLog(@"source changed");
                // The Patcher writes several files in quick succession; let the
                // burst settle so one batch produces one notification. Extra
                // firings are harmless — RunSync copies only what is missing and
                // stays silent when that is nothing.
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), q, ^{
                    RunSync();
                });
            });
            dispatch_source_set_cancel_handler(sVnode, ^{ close(fd); });
            dispatch_resume(sVnode);
            RHDLog(@"watching %@", src);
        }

        // Backstop. The kqueue is the fast path, but a daemon that quietly stops
        // receiving events would lose debs silently, and this archive exists
        // precisely because the cache is not durable. Ten minutes of latency in
        // the worst case is a fair price for that guarantee.
        static dispatch_source_t sPoll;
        sPoll = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
        dispatch_source_set_timer(sPoll, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC),
                                  600 * NSEC_PER_SEC, 60 * NSEC_PER_SEC);
        dispatch_source_set_event_handler(sPoll, ^{ RunSync(); });
        dispatch_resume(sPoll);

        // Manual kick: notifyutil -p com.guacforlife.rhdarchived.sync
        static int token;
        notify_register_dispatch(NOTIFY_SYNC, &token, q, ^(int t) { RunSync(); });

        dispatch_main();
    }
    return 0;
}
