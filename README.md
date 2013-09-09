#RILAnalyzer tool

The rilAnalyzer is a set of android processes that provides cross-layer
monitoring tools for user-app-cell net interactions. It can be used to identify
app inefficiencies, debugging and also for monitoring apps for research
purposes.

Implemente by:

_Narseo Vallina-Rodriguez_

ICSI-Berkeley and University of Cambridge

narseo@gmail.com

_Andrius Aucinas_

University of Cambridge

andrius.aucinas@gmail.com

_Yan Grunenberger_

Telefonica Research

yan@tid.es

Collaborators: Jon Crowcroft (University of Cambridge) and Dina Papagiannaki
(Telefonica Research). We would like to thank as well the help of Armando
Garcia-Mendoza (Telefonica Research) on an earlier attempt.

The current version only supports xgoldmon chipsets. See our IMC'13 paper for more details about its goals, features and limitations. [Paper] (http://www.cl.cam.ac.uk/~nv240/papers/imc117-vallina.pdf). If the tool is used for academic purposes, we would appreciate if you cite it.

Current instalation process is tedious due to OS permissions. See instructions
below. Please refer to the [wiki](https://github.com/narseo/ril_analyzer/wiki/) for more detailed information on the rilAnalyzer architecture. See logger process and networklog to see the structure of the different logging files (we will update that on the wiki soon).

#RILAnalyzer APK

Android APK for monitoring RNC events. It directly polls the radio interface to
collect RNC state. This APK has to run as a system service because of Android permissions. 

Runs as a background service launched on boot by the OS. Data output is written on /sdcard/ril_log.txt by logger process (See below). The logging procedure be customized and quite improved.

#Networklog APK

Traffic monitor app exploiting iptables _nflog_ feature. It collects mobile traffic at IP level. The current version is a customised extention of [PRAGMA Networklog] app (https://github.com/pragma-/networklog)

This APK has to be launched by the user for the first time and then modify the app settings to launch it automatically on boot. Data output is written by itself on /sdcard/networklog.txt (can be customized).

It also makes sure that required processes (e.g. iptables flags) are set up correctly.

#Logger Binary

Binary (c) that runs in the background and reads UDP packets from RILAnalyzr and saves them on the SD Card.

Requires Android NDK for building it.

#Transparent proxy

Rudimentary transparent proxy to collect data using a transparent tun
interface. It was the first attempt before using networklog.

Requires Android NDK for building it. Use same process as logger binary to
install it on the phone and follow the steps described in the wiki to [set up
a tun interface on android] (https://github.com/narseo/ril_analyzer/wiki/How-to-create-a-transparent-proxy-with-a-tun-interface) 

#Building and Instalation:

__IMPORTANT__: __Requires rooted devices.__

Install Android SDK and NDK.

Create and import projects separately on Eclipse.

Remove Samsung Service Mode:

$adb shell mount -o rw,remount /system
$adb shell rm /system/app/SamsungServiceMode.apk
$adb shell mount -o ro,remount /system


Build logger process using Android NDK (with the right target). It is required for storing RNC events on /sdcard/. To install, move the binary to /system/ so it is automatically launched on boot:

$adb shell mount -o rw,remount /system
$adb push SOURCE_LOGGER /system/bin/
$adb shell mount -o ro,remount /system

Use ADB to put send APKs to mobile handset: 

$adb shell mount -o rw,remount /system
$adb push source_rilanalyzer_apk /system/app/
$adb push source_networklog_apk /system/app/
$adb shell mount -o ro,remount /system

Reboot handset:

$adb reboot

Launch Networklog manually. RILAnalyzer and logger binary should be automatically launched on boot. To stop and remove all the logging capabilities, remove the files manually (mount filesystem with the right permisions accordingly):

$adb shell rm PATH_TO_APK/BINARY

#Warning

The logging processes are very CPU and memory intense. The battery life of the handset can be negatively affected. The main problem is the lack of firmware and OS support. RIL events have to be polled directly from the OS.

For further details, suggestions and collaborations, do not hesitate to contact us.
