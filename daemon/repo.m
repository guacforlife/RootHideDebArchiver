// repo.m — flat APT repo over the archived deb cache, served on loopback so
// Sileo can reinstall anything the Patcher has ever converted.
//
// Deliberately self-contained: the device has no dpkg-scanpackages (no perl),
// no python3 and no HTTP server, so the index is built from `dpkg-deb -f` plus
// an in-process SHA256, and the server is ~150 lines of BSD sockets. The only
// external binaries used are dpkg-deb and gzip, both already on device.

#import "repo.h"
#include <CommonCrypto/CommonDigest.h>
#include <spawn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <string.h>

extern char **environ;

static NSString *gRepoDir, *gDebDir, *gJBRoot;
static NSString *const kRepoLog = @"/var/tmp/.rhdarchived.log";

static void RepoLog(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *line = [NSString stringWithFormat:@"%@ repo: %@\n",
                      [[NSISO8601DateFormatter new] stringFromDate:[NSDate date]], msg];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:kRepoLog];
    if (!fh) { [line writeToFile:kRepoLog atomically:NO encoding:NSUTF8StringEncoding error:nil]; return; }
    [fh seekToEndOfFile];
    [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

void RHDRepoConfigure(NSString *repoDir, NSString *debDir, NSString *jbroot) {
    gRepoDir = repoDir; gDebDir = debDir; gJBRoot = jbroot;
    [[NSFileManager defaultManager] createDirectoryAtPath:repoDir
                              withIntermediateDirectories:YES attributes:nil error:nil];
}

#pragma mark - running helper binaries

// posix_spawn + pipe. NSTask is not available on iOS, and the pipe MUST be
// drained before waitpid or a control stanza larger than the pipe buffer
// deadlocks the daemon.
static NSString *RunCapturing(NSString *tool, NSArray<NSString *> *args) {
    NSString *path = [gJBRoot stringByAppendingPathComponent:tool];
    int fds[2];
    if (pipe(fds) != 0) return nil;

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclose(&fa, fds[0]);

    NSMutableArray *all = [NSMutableArray arrayWithObject:path];
    [all addObjectsFromArray:args];
    char **argv = calloc(all.count + 1, sizeof(char *));
    for (NSUInteger i = 0; i < all.count; i++) argv[i] = strdup([all[i] UTF8String]);

    pid_t pid = 0;
    int rc = posix_spawn(&pid, [path fileSystemRepresentation], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    for (NSUInteger i = 0; i < all.count; i++) free(argv[i]);
    free(argv);
    if (rc != 0) { close(fds[0]); return nil; }

    NSMutableData *out = [NSMutableData data];
    char buf[8192];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof(buf))) > 0) [out appendBytes:buf length:(NSUInteger)n];
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return nil;
    return [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
}

static BOOL RunRedirecting(NSString *tool, NSArray<NSString *> *args, NSString *stdoutPath) {
    NSString *path = [gJBRoot stringByAppendingPathComponent:tool];
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, [stdoutPath fileSystemRepresentation],
                                     O_WRONLY | O_CREAT | O_TRUNC, 0644);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    NSMutableArray *all = [NSMutableArray arrayWithObject:path];
    [all addObjectsFromArray:args];
    char **argv = calloc(all.count + 1, sizeof(char *));
    for (NSUInteger i = 0; i < all.count; i++) argv[i] = strdup([all[i] UTF8String]);

    pid_t pid = 0;
    int rc = posix_spawn(&pid, [path fileSystemRepresentation], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    for (NSUInteger i = 0; i < all.count; i++) free(argv[i]);
    free(argv);
    if (rc != 0) return NO;
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static NSString *SHA256OfFile(NSString *path) {
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return nil;
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    while (1) {
        @autoreleasepool {
            NSData *chunk = [fh readDataOfLength:1024 * 1024];
            if (!chunk.length) break;
            CC_SHA256_Update(&ctx, chunk.bytes, (CC_LONG)chunk.length);
        }
    }
    [fh closeFile];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

#pragma mark - index generation

// Rebuilding from scratch means 137 dpkg-deb spawns plus hashing 681 MB, so
// results are cached by (name, size). A sync that adds one deb then costs one
// spawn, not a full rescan.
static NSString *CachePath(void) { return [gRepoDir stringByAppendingPathComponent:@".index-cache.json"]; }

static NSMutableDictionary *LoadCache(void) {
    NSData *d = [NSData dataWithContentsOfFile:CachePath()];
    if (!d) return [NSMutableDictionary dictionary];
    id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    return [j isKindOfClass:NSDictionary.class] ? [j mutableCopy] : [NSMutableDictionary dictionary];
}

// Strips fields we are about to compute ourselves, so a deb that was already
// published in some other repo cannot inject a stale Filename or checksum.
static NSString *CleanControl(NSString *control) {
    NSArray *drop = @[@"Filename:", @"Size:", @"MD5sum:", @"SHA1:", @"SHA256:", @"SHA512:"];
    NSMutableArray *keep = [NSMutableArray array];
    BOOL skipping = NO;
    for (NSString *line in [control componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:@" "] || [line hasPrefix:@"\t"]) {   // continuation
            if (!skipping) [keep addObject:line];
            continue;
        }
        skipping = NO;
        for (NSString *f in drop) {
            if ([line hasPrefix:f]) { skipping = YES; break; }
        }
        if (!skipping && line.length) [keep addObject:line];
    }
    return [keep componentsJoinedByString:@"\n"];
}

void RHDRepoRefresh(void) {
    if (!gRepoDir || !gDebDir) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *names = [[fm contentsOfDirectoryAtPath:gDebDir error:nil]
                      sortedArrayUsingSelector:@selector(compare:)];
    if (!names) return;

    NSMutableDictionary *cache = LoadCache();
    NSMutableDictionary *fresh = [NSMutableDictionary dictionary];
    NSMutableString *packages = [NSMutableString string];
    NSUInteger built = 0, reused = 0;

    for (NSString *name in names) {
        @autoreleasepool {
            if (![[name pathExtension] isEqualToString:@"deb"]) continue;
            NSString *full = [gDebDir stringByAppendingPathComponent:name];
            NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
            if (!attrs) continue;
            unsigned long long size = [attrs fileSize];

            NSDictionary *hit = cache[name];
            NSString *control = nil, *sha = nil;
            if (hit && [hit[@"size"] unsignedLongLongValue] == size) {
                control = hit[@"control"]; sha = hit[@"sha256"]; reused++;
            } else {
                control = RunCapturing(@"usr/bin/dpkg-deb", @[@"-f", full]);
                if (!control.length) { RepoLog(@"unreadable, skipped: %@", name); continue; }
                control = CleanControl(control);
                sha = SHA256OfFile(full);
                built++;
            }
            if (!control.length || !sha.length) continue;
            fresh[name] = @{@"size": @(size), @"sha256": sha, @"control": control};

            [packages appendString:control];
            [packages appendString:@"\n"];
            // Served through the /debs/ route, which maps back to the cache
            // directory — the debs are never copied into the repo directory.
            [packages appendFormat:@"Filename: debs/%@\n", name];
            [packages appendFormat:@"Size: %llu\n", size];
            [packages appendFormat:@"SHA256: %@\n\n", sha];
        }
    }

    NSString *pkgPath = [gRepoDir stringByAppendingPathComponent:@"Packages"];
    NSString *existing = [NSString stringWithContentsOfFile:pkgPath encoding:NSUTF8StringEncoding error:nil];
    if ([existing isEqualToString:packages]) return;   // nothing changed

    [packages writeToFile:pkgPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    // gzip -kf leaves the plain file in place; Sileo tries Packages.gz first and
    // falls back to Packages.
    NSString *gzFinal = [gRepoDir stringByAppendingPathComponent:@"Packages.gz"];
    NSString *gzTmp = [gRepoDir stringByAppendingPathComponent:@".Packages.gz.tmp"];
    [fm removeItemAtPath:gzTmp error:nil];
    if (RunRedirecting(@"usr/bin/gzip", @[@"-9", @"-c", pkgPath], gzTmp)) {
        [fm removeItemAtPath:gzFinal error:nil];
        [fm moveItemAtPath:gzTmp toPath:gzFinal error:nil];   // atomic swap
    } else {
        [fm removeItemAtPath:gzTmp error:nil];
        RepoLog(@"gzip failed, leaving previous Packages.gz in place");
    }

    // Release is written last: APT warns "No Hash entry" and "Invalid 'Date'
    // entry" without these, so both index files have to exist to be hashed.
    NSDateFormatter *df = [NSDateFormatter new];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    df.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss 'UTC'";

    NSMutableString *release = [NSMutableString stringWithFormat:
        @"Origin: RootHide Patcher Cache\n"
        @"Label: roothide-deb-cache\n"
        @"Suite: stable\n"
        @"Version: 1.0\n"
        @"Codename: ios\n"
        @"Architectures: iphoneos-arm64e\n"
        @"Components: main\n"
        @"Date: %@\n"
        @"Description: Every deb the RootHide Patcher has converted on this device\n"
        @"SHA256:\n", [df stringFromDate:[NSDate date]]];
    for (NSString *idx in @[@"Packages", @"Packages.gz"]) {
        NSString *p = [gRepoDir stringByAppendingPathComponent:idx];
        NSDictionary *a = [fm attributesOfItemAtPath:p error:nil];
        NSString *h = a ? SHA256OfFile(p) : nil;
        if (h) [release appendFormat:@" %@ %llu %@\n", h, [a fileSize], idx];
    }
    [release writeToFile:[gRepoDir stringByAppendingPathComponent:@"Release"]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];

    NSData *cj = [NSJSONSerialization dataWithJSONObject:fresh options:0 error:nil];
    [cj writeToFile:CachePath() atomically:YES];

    RepoLog(@"index rebuilt: %lu packages (%lu read, %lu cached)",
            (unsigned long)fresh.count, (unsigned long)built, (unsigned long)reused);
}

#pragma mark - loopback HTTP server

static NSString *URLDecode(NSString *s) {
    return [s stringByRemovingPercentEncoding] ?: s;
}

static void SendAll(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return;
        p += n; len -= (size_t)n;
    }
}

static void SendStatus(int fd, const char *status) {
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    SendAll(fd, hdr, (size_t)n);
}

static void ServeFile(int fd, NSString *path, BOOL headOnly, NSString *ifNoneMatch) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (!attrs || [attrs fileType] != NSFileTypeRegular) { SendStatus(fd, "404 Not Found"); return; }
    unsigned long long size = [attrs fileSize];
    BOOL isDeb = [path hasSuffix:@".deb"];
    const char *type = isDeb ? "application/x-debian-package" : "text/plain";

    // Cache validators are not optional here. Sileo fetches through URLSession,
    // which applies HEURISTIC caching when a response carries no Last-Modified,
    // ETag or Cache-Control — so it can keep serving its own stale copy of the
    // index indefinitely while curl and apt (which don't cache) always see fresh
    // data. That mismatch is exactly what "the repo won't update in Sileo" looks
    // like. Indexes must revalidate; debs are immutable per filename.
    time_t mtime = (time_t)[[attrs fileModificationDate] timeIntervalSince1970];
    char etag[128];
    snprintf(etag, sizeof(etag), "\"%llx-%llx\"", size, (unsigned long long)mtime);
    if (ifNoneMatch.length && [ifNoneMatch containsString:[NSString stringWithUTF8String:etag]]) {
        char h304[256];
        int n304 = snprintf(h304, sizeof(h304),
                            "HTTP/1.1 304 Not Modified\r\nETag: %s\r\n"
                            "Cache-Control: no-cache, must-revalidate\r\n"
                            "Connection: close\r\n\r\n", etag);
        SendAll(fd, h304, (size_t)n304);
        return;
    }

    char lastmod[64];
    struct tm gmt;
    gmtime_r(&mtime, &gmt);
    strftime(lastmod, sizeof(lastmod), "%a, %d %b %Y %H:%M:%S GMT", &gmt);

    char hdr[768];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %llu\r\n"
                     "Last-Modified: %s\r\nETag: %s\r\nCache-Control: %s\r\n"
                     "Connection: close\r\n\r\n",
                     type, size, lastmod, etag,
                     isDeb ? "public, max-age=31536000" : "no-cache, must-revalidate");
    SendAll(fd, hdr, (size_t)n);
    if (headOnly) return;

    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return;
    while (1) {
        @autoreleasepool {
            NSData *chunk = [fh readDataOfLength:256 * 1024];
            if (!chunk.length) break;
            SendAll(fd, chunk.bytes, chunk.length);
        }
    }
    [fh closeFile];
}

// Closing a socket that still has unread bytes queued makes TCP send RST, which
// DISCARDS anything still in the send buffer — the client sees a truncated body.
// A keep-alive client that pipelines a second request (URLSession does; curl in
// these tests did not) trips this on large responses. Shut down the write side,
// drain briefly, then close.
static void LingeringClose(int fd) {
    shutdown(fd, SHUT_WR);
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char sink[4096];
    while (read(fd, sink, sizeof(sink)) > 0) { }
    close(fd);
}

static void HandleConnection(int fd) {
    // A client that vanishes mid-transfer would otherwise SIGPIPE the daemon;
    // KeepAlive would respawn it, which reads as random restarts.
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

    // Headers only; this server has no request bodies to read.
    char buf[8192];
    size_t used = 0;
    while (used < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (!used) { LingeringClose(fd); return; }
    buf[used] = 0;

    char method[16] = {0}, target[2048] = {0};
    if (sscanf(buf, "%15s %2047s", method, target) != 2) { SendStatus(fd, "400 Bad Request"); LingeringClose(fd); return; }
    BOOL headOnly = strcmp(method, "HEAD") == 0;
    NSString *ifNoneMatch = nil;
    { const char *h = strcasestr(buf, "\r\nIf-None-Match:");
      if (h) { h += 17; while (*h == ' ') h++;
               const char *e = strstr(h, "\r\n");
               if (e) ifNoneMatch = [[NSString alloc] initWithBytes:h length:(NSUInteger)(e-h)
                                                          encoding:NSUTF8StringEncoding]; } }
    if (strcmp(method, "GET") != 0 && !headOnly) { SendStatus(fd, "405 Method Not Allowed"); LingeringClose(fd); return; }

    NSString *reqPath = URLDecode([NSString stringWithUTF8String:target]);
    NSRange q = [reqPath rangeOfString:@"?"];
    if (q.location != NSNotFound) reqPath = [reqPath substringToIndex:q.location];
    if (![reqPath hasPrefix:@"/"]) { SendStatus(fd, "403 Forbidden"); LingeringClose(fd); return; }

    // A flat repo (Suites: ./) makes APT ask for "/./Packages", so "." segments
    // have to be collapsed — exact-match routing 404s the real client even
    // though curl works, because curl normalises client-side and APT does not.
    // Done per component: ".." is rejected outright (after percent-decoding, so
    // "..%2f" cannot slip through) while a legitimate name containing dots is
    // left alone.
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *c in [reqPath componentsSeparatedByString:@"/"]) {
        if (!c.length || [c isEqualToString:@"."]) continue;
        if ([c isEqualToString:@".."]) { SendStatus(fd, "403 Forbidden"); LingeringClose(fd); return; }
        [parts addObject:c];
    }
    NSString *rel = [parts componentsJoinedByString:@"/"];
    NSString *target_path = nil;
    if ([rel hasPrefix:@"debs/"]) {
        NSString *name = [rel substringFromIndex:5];
        if ([name containsString:@"/"] || !name.length) { SendStatus(fd, "403 Forbidden"); LingeringClose(fd); return; }
        target_path = [gDebDir stringByAppendingPathComponent:name];
    } else if ([rel isEqualToString:@"Packages"] || [rel isEqualToString:@"Packages.gz"] ||
               [rel isEqualToString:@"Release"]) {
        target_path = [gRepoDir stringByAppendingPathComponent:rel];
    } else {
        SendStatus(fd, "404 Not Found"); close(fd); return;
    }

    ServeFile(fd, target_path, headOnly, ifNoneMatch);
    LingeringClose(fd);
}

void RHDRepoServe(uint16_t port) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { RepoLog(@"socket failed: %s", strerror(errno)); return; }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // Sileo is on this device; never expose to the LAN
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        RepoLog(@"bind :%u failed: %s", port, strerror(errno)); close(lfd); return;
    }
    if (listen(lfd, 16) != 0) { RepoLog(@"listen failed: %s", strerror(errno)); close(lfd); return; }

    // Static, like the watcher source — an ARC-released local would tear the
    // listener down the moment this function returns.
    static dispatch_source_t sAccept;
    static dispatch_queue_t sConnQ;
    sConnQ = dispatch_queue_create("com.guacforlife.rhdarchived.http", DISPATCH_QUEUE_CONCURRENT);
    sAccept = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)lfd, 0,
                                     dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_event_handler(sAccept, ^{
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) return;
        dispatch_async(sConnQ, ^{ @autoreleasepool { HandleConnection(cfd); } });
    });
    dispatch_resume(sAccept);
    RepoLog(@"serving http://127.0.0.1:%u/ from %@", port, gRepoDir);
}
