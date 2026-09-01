// repo.h — turns the archived deb cache into a flat APT repo Sileo can install from.
#import <Foundation/Foundation.h>

// debDir is served read-only; repoDir holds the generated index. They are kept
// SEPARATE on purpose: the daemon kqueue-watches debDir, so writing an index
// into it would retrigger the watcher on every regeneration.
void RHDRepoConfigure(NSString *repoDir, NSString *debDir, NSString *jbroot);

// Regenerates Release/Packages/Packages.gz when the set of debs has changed.
// Cheap to call on every sync — unchanged files are served from a cache.
void RHDRepoRefresh(void);

// Starts the loopback HTTP server. Safe to call once, at startup.
void RHDRepoServe(uint16_t port);
