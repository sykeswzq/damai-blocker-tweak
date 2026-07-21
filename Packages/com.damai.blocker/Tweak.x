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

%hook stat
int stat(const char *pathname, struct stat *buf) {
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return %orig;
}
%end

%hook lstat
int lstat(const char *pathname, struct stat *buf) {
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return %orig;
}
%end

%hook access
int access(const char *pathname, int mode) {
    if (dam_is_jb(pathname)) return -1;
    return %orig;
}
%end

%hook faccessat
int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (dam_is_jb(pathname)) return -1;
    return %orig;
}
%end

%hook open
int open(const char *pathname, int flags, ...) {
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return %orig;
}
%end

%hook openat
int openat(int dirfd, const char *pathname, int flags, ...) {
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return %orig;
}
%end

%hook fopen
FILE *fopen(const char *filename, const char *mode) {
    if (dam_is_jb(filename)) { errno = ENOENT; return NULL; }
    return %orig;
}
%end

%hook fopen64
FILE *fopen64(const char *filename, const char *mode) {
    if (dam_is_jb(filename)) { errno = ENOENT; return NULL; }
    return %orig;
}
%end

%hook readlink
ssize_t readlink(const char *pathname, char *buf, size_t bufsize) {
    if (dam_is_jb(pathname)) { errno = ENOENT; return -1; }
    return %orig;
}
%end

%hook dlopen
void *dlopen(const char *path, int mode) {
    if (dam_is_jb(path)) { errno = ENOENT; return NULL; }
    return %orig;
}
%end

%hook getenv
char *getenv(const char *name) {
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
    return %orig;
}
%end

%hook putenv
int putenv(char *string) {
    if (string && strncmp(string, "DYLD_", 5) == 0) return 0;
    if (string && strncmp(string, "SUBLIBRARYPATH=", 14) == 0) return 0;
    return %orig;
}
%end

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
