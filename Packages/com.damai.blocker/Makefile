# THEOS can be set via environment (e.g. GitHub Actions) or default
ifndef THEOS
THEOS ?= $(HOME)/theos
endif

ARCHS := arm64 arm64e
TARGET := iphone:clang:latest:16.0

TWEAK_NAME = DamaiBlocker

DamaiBlocker_FILES = Tweak.x
DamaiBlocker_CFLAGS = -fobjc-arc -arch arm64 -arch arm64e
DamaiBlocker_LDFLAGS = -F$(THEOS)/lib -framework UIKit -framework Foundation -framework CoreFoundation

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

COMPATIBILITY_VERSION_SCHEME := ios
COMPATIBILITY_VERSION := ios16.0
