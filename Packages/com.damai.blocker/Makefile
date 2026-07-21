ARCHS := arm64 arm64e
TARGET := iphone:clang:latest:16.0

TWEAK_NAME = DamaiBlocker
DamaiBlocker_FILES = Tweak.x
DamaiBlocker_CFLAGS = -fobjc-arc
DamaiBlocker_LDFLAGS = -F$(THEOS)/lib -framework UIKit -framework Foundation -framework CoreFoundation

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
