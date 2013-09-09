#Narseo Vallina-Rodriguez. 
#University of Cambridge

MY_DIR:= $(call my-dir)
LOCAL_PATH := $(MY_DIR)

# first lib, which will be built statically
#
include $(CLEAR_VARS)

LOCAL_SHARED_LIBRARIES := libcutils liblog
LOCAL_MODULE    := spectrumutils
LOCAL_SRC_FILES := spectrumutils.c

LOCAL_MODULE_TAGS := eng

include $(BUILD_STATIC_LIBRARY)

# second lib, which will depend on and include the first one
#

LOCAL_PATH := $(MY_DIR)

include $(CLEAR_VARS)

LOCAL_SHARED_LIBRARIES := libcutils liblog
LOCAL_MODULE    := transparentproxy
LOCAL_SRC_FILES := transparentproxy.c
LOCAL_STATIC_LIBRARIES := spectrumutils
LOCAL_MODULE_TAGS := eng

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
