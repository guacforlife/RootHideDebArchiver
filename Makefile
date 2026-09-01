THEOS ?= $(HOME)/theos
export THEOS
export ARCHS = arm64 arm64e
# 14.0, not 16.0: with a 16.0 minimum, clang's ARC emits
# objc_claimAutoreleasedReturnValue, which the 14.5 SDK's libobjc does not
# export, and the link fails. Nothing here needs anything newer than iOS 10.
export TARGET = iphone:clang:14.5:14.0
THEOS_PACKAGE_SCHEME = rootless

TOOL_NAME = rhdarchived
rhdarchived_FILES = daemon/main.m daemon/repo.m
rhdarchived_CFLAGS = -fobjc-arc
rhdarchived_FRAMEWORKS = Foundation
rhdarchived_CODESIGN_FLAGS = -Sents.plist
rhdarchived_INSTALL_PATH = /usr/local/libexec

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tool.mk
