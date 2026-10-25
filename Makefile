TARGET := iphone:clang:16.5:15.0
ARCHS := arm64 arm64e

# Hỗ trợ Roothide & Rootless (Mặc định Rootless để tương thích tiêm Sideloadly)
THEOS_PACKAGE_SCHEME ?= rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Zalotweak

Zalotweak_FILES = src/Tweak.x src/SecurityManager.m src/FloatingMenu.m src/DeviceProfilePool.m src/fishhook.c src/ZTDiagnosticViewController.m src/BackupManager.m
Zalotweak_CFLAGS = -fobjc-arc -Isrc -Wno-deprecated-declarations -Wno-error -Wno-frame-address -fvisibility=hidden -fvisibility-inlines-hidden
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
Zalotweak_CFLAGS += -DTHEOS_PACKAGE_SCHEME_ROOTHIDE=1
endif
Zalotweak_LDFLAGS = -Wl,-dead_strip -Wl,-x -Wl,-S
Zalotweak_LIBRARIES = z
Zalotweak_FRAMEWORKS = UIKit Foundation Security SystemConfiguration AdSupport AppTrackingTransparency CoreTelephony Intents CFNetwork UserNotifications

include $(THEOS_MAKE_PATH)/tweak.mk

SUBPROJECTS += zalotweakprefs
include $(THEOS_MAKE_PATH)/aggregate.mk
