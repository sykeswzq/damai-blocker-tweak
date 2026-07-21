/*
 * DamaiBlocker - bypass jailbreak detection for 大麦 (cn.damai.iphone)
 * Target: iOS 16.5 + Dopamine Rootless + ElleKit
 * Device: iPhone 14 Pro (arm64e)
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <strings.h>
#import <errno.h>
#import <fcntl.h>
#import <stdarg.h>

static int dam_is_jb(const char *p) {
    if (!p) return 0;
    const char *j[] = {
        "/var/jb", "/Library/MobileSubstrate",
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Filza.app", "/private/var/lib/apt/",
        "/private/var/stash", "/etc/apt", "/bin/bash",
        "/bin/sh", "/usr/bin/su", "/usr/sbin/sshd",
        "/usr/bin/ssh", "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libsubstrate.dylib", "/Library/PreferenceLoader",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/var/jb/Library/MobileSubstrate/DynamicLibraries",
        "/var/jb/etc/apt",
    };
    for (int i = 0; i < (int)(sizeof(j)/sizeof(j[0])); i++) {
        if (strstr(p, j[i])) return 1;
    }
    return 0;
}

#pragma mark - C function hooks via dlsym

typedef int (*real_stat_t)(const char *, struct stat *);
typedef int (*real_lstat_t)(const char *, struct stat *);
typedef int (*real_access_t)(const char *, int);
typedef int (*real_faccessat_t)(int, const char *, int, int);
typedef int (*real_open_t)(const char *, int, ...);
typedef int (*real_openat_t)(int, const char *, int, ...);
typedef FILE *(*real_fopen_t)(const char *, const char *);
typedef FILE *(*real_fopen64_t)(const char *, const char *);
typedef ssize_t (*real_readlink_t)(const char *, char *, size_t);
typedef void *(*real_dlopen_t)(const char *, int);
typedef char *(*real_getenv_t)(const char *);
typedef int (*real_putenv_t)(char *);

static real_stat_t      orig_stat = NULL;
static real_lstat_t     orig_lstat = NULL;
static real_access_t    orig_access = NULL;
static real_faccessat_t orig_faccessat = NULL;
static real_open_t      orig_open = NULL;
static real_openat_t    orig_openat = NULL;
static real_fopen_t     orig_fopen = NULL;
static real_fopen64_t   orig_fopen64 = NULL;
static real_readlink_t  orig_readlink = NULL;
static real_dlopen_t    orig_dlopen = NULL;
static real_getenv_t    orig_getenv = NULL;
static real_putenv_t    orig_putenv = NULL;

static void ensure_orig(void) {
    if (orig_stat == NULL)  orig_stat = (real_stat_t)dlsym(RTLD_NEXT, "stat");
    if (orig_lstat == NULL) orig_lstat = (real_lstat_t)dlsym(RTLD_NEXT, "lstat");
    if (orig_access == NULL) orig_access = (real_access_t)dlsym(RTLD_NEXT, "access");
    if (orig_faccessat == NULL) orig_faccessat = (real_faccessat_t)dlsym(RTLD_NEXT, "faccessat");
    if (orig_open == NULL)  orig_open = (real_open_t)dlsym(RTLD_NEXT, "open");
    if (orig_openat == NULL) orig_openat = (real_openat_t)dlsym(RTLD_NEXT, "openat");
    if (orig_fopen == NULL) orig_fopen = (real_fopen_t)dlsym(RTLD_NEXT, "fopen");
    if (orig_fopen64 == NULL) orig_fopen64 = (real_fopen64_t)dlsym(RTLD_NEXT, "fopen64");
    if (orig_readlink == NULL) orig_readlink = (real_readlink_t)dlsym(RTLD_NEXT, "readlink");
    if (orig_dlopen == NULL) orig_dlopen = (real_dlopen_t)dlsym(RTLD_NEXT, "dlopen");
    if (orig_getenv == NULL) orig_getenv = (real_getenv_t)dlsym(RTLD_NEXT, "getenv");
    if (orig_putenv == NULL) orig_putenv = (real_putenv_t)dlsym(RTLD_NEXT, "putenv");
}

int stat(const char *pathname, struct stat *buf) {
    ensure_orig();
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return orig_stat(pathname, buf);
}

int lstat(const char *pathname, struct stat *buf) {
    ensure_orig();
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return orig_lstat(pathname, buf);
}

int access(const char *pathname, int mode) {
    ensure_orig();
    if (dam_is_jb(pathname)) return -1;
    return orig_access(pathname, mode);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    ensure_orig();
    if (dam_is_jb(pathname)) return -1;
    return orig_faccessat(dirfd, pathname, mode, flags);
}

int open(const char *pathname, int flags, ...) {
    ensure_orig();
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        m = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return orig_open(pathname, flags, m);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    ensure_orig();
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        m = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return orig_openat(dirfd, pathname, flags, m);
}

FILE *fopen(const char *filename, const char *mode) {
    ensure_orig();
    if (dam_is_jb(filename)) { errno = ENOENT; return NULL; }
    return orig_fopen(filename, mode);
}

FILE *fopen64(const char *filename, const char *mode) {
    ensure_orig();
    if (dam_is_jb(filename)) { errno = ENOENT; return NULL; }
    return orig_fopen64(filename, mode);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsize) {
    ensure_orig();
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return orig_readlink(pathname, buf, bufsize);
}

void *dlopen(const char *path, int mode) {
    ensure_orig();
    if (dam_is_jb(path)) { errno = ENOENT; return NULL; }
    return orig_dlopen(path, mode);
}

char *getenv(const char *name) {
    ensure_orig();
    if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
        strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
        strcmp(name, "DYLD_FALLBACK_LIBRARY_PATH") == 0 ||
        strcmp(name, "DYLD_FRAMEWORK_PATH") == 0 ||
        strcmp(name, "SUBLIBRARYPATH") == 0 ||
        strcmp(name, "MobileSubstrateEnablePath") == 0 ||
        strcmp(name, "CydiaSubstrateEnabled") == 0 ||
        strcmp(name, "ElleKitVersion") == 0 ||
        strcmp(name, "SubstituteVersion") == 0) {
        return NULL;
    }
    return orig_getenv(name);
}

int putenv(char *string) {
    ensure_orig();
    if (string && strncmp(string, "DYLD_", 5) == 0) return 0;
    if (string && strncmp(string, "SUBLIBRARYPATH=", 14) == 0) return 0;
    return orig_putenv(string);
}

#pragma mark - ObjC hooks

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (dam_is_jb([path UTF8String])) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    if (dam_is_jb([path UTF8String])) return NO;
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (dam_is_jb([path UTF8String])) return NO;
    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if (dam_is_jb([path UTF8String])) return NO;
    return %orig;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (dam_is_jb([path UTF8String])) return @[];
    return %orig;
}
%end

%hook NSBundle

+ (NSBundle *)bundleWithPath:(NSString *)path {
    if (dam_is_jb([path UTF8String])) return nil;
    return %orig;
}

+ (NSBundle *)bundleForClass:(Class)aClass {
    NSBundle *b = %orig;
    if (b && [[b bundlePath] hasPrefix:@"/var/jb"]) return nil;
    return b;
}
%end

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    NSString *s = url.scheme ? [url.scheme lowercaseString] : @"";
    NSArray *blocked = @[ @"cydia", @"sileo", @"zibra", @"filza", @"sbsettings", @"duck", @"installion", @"ifile" ];
    for (NSString *b in blocked) {
        if ([s isEqualToString:b]) return NO;
    }
    return %orig;
}

- (BOOL)openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options completionHandler:(void (^)(BOOL))completionHandler {
    NSString *s = url.scheme ? [url.scheme lowercaseString] : @"";
    NSArray *blocked = @[ @"cydia", @"sileo", @"zibra", @"filza", @"sbsettings", @"duck", @"installion", @"ifile" ];
    for (NSString *b in blocked) {
        if ([s isEqualToString:b]) {
            NSLog(@"[DamaiBlocker] Blocked URL: %@", url);
            if (completionHandler) completionHandler(NO);
            return YES;
        }
    }
    return %orig;
}

- (BOOL)openURL:(NSURL *)url {
    NSString *s = url.scheme ? [url.scheme lowercaseString] : @"";
    NSArray *blocked = @[ @"cydia", @"sileo", @"zibra", @"filza", @"sbsettings", @"duck", @"installion", @"ifile" ];
    for (NSString *b in blocked) {
        if ([s isEqualToString:b]) {
            NSLog(@"[DamaiBlocker] Blocked URL: %@", url);
            return NO;
        }
    }
    return %orig;
}
%end

%ctor {
    printf("[DamaiBlocker] Tweak loaded successfully\n");
    NSLog(@"[DamaiBlocker] Loaded for bundle: cn.damai.iphone");
}
