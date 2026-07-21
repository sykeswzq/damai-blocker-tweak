# DamaiBlocker - 大麦越狱检测绕过

## 目标应用
- 应用：大麦 (Damai)
- Bundle ID: `cn.damai.iphone`
- 版本: 9.0.27

## 设备环境
- iPhone 14 Pro (A16, arm64e)
- iOS 16.5
- Dopamine Rootless 越狱
- Sileo 软件包管理器
- ElleKit (Substitute/Cydia Substrate 替代)

## 功能
- Hook stat/lstat/access/open/readlink/dlopen 等系统调用，隐藏越狱特征文件
- 隐藏 Cydia/Sileo/Filza 等越狱应用 URL Scheme
- 隐藏 DYLD_ 环境变量和 ElleKit/ElleKit 相关变量

## 安装
将生成的 `.deb` 文件安装到 Sileo 即可。重启后生效。
