TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = Roblox

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Spork
Spork_FILES = Tweak.xm SporkUI.mm hooks.mm
Spork_OBJCFLAGS = -fobjc-arc
Spork_OBJCCFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
