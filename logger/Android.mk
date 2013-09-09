# Copyright 2012 Narseo Vallina-Rodriguez. University of Cambridge

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= logger.c

LOCAL_SHARED_LIBRARIES := liblog libcutils

LOCAL_MODULE:= logger

LOCAL_MODULE_TAGS := eng

include $(BUILD_EXECUTABLE)
