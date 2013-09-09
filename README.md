#RILAnalyzer. 

The rilAnalyzer is a set of android processes that provides cross-layer
monitoring tools for user-app-cell net interactions. It can be used to identify
app inefficiencies, debugging and also for monitoring apps for research
purposes.

Implemente by:

_Narseo Vallina-Rodriguez_
ICSI-Berkeley and University of Cambridge
email: narseo@gmail.com

_Andrius Aucinas_
University of Cambridge
andrius.aucinas@gmail.com

_Yan Grunenberger_
Telefonica Research
yan@tid.es

Collaborators: Jon Crowcroft (University of Cambridge) and Dina Papagiannaki
(Telefonica Research). We would like to thank as well the help of Armando
Garcia-Mendoza (Telefonica Research) on an earlier attempt.

The current version only supports xgoldmon chipsets. See our IMC'13 paper for more details about its goals, features and limitations. [Paper] (http://www.cl.cam.ac.uk/~nv240/papers/imc117-vallina.pdf)

Current instalation process is tedious due to OS permissions. See instructions
below. Please refer to the [System Overview](https://github.com/narseo/rilAnalyzer/wiki/System-Overview) for more detailed information on the rilAnalyzer architecture.

#RILAnalyzer APK. 

Android APK version for monitoring RNC events.

Runs as a background service launched on boot by the OS. Data output is written on /sdcard/ril_log.txt (can be customized)

It has to run as a system service because of permissions. Current version requires a background service (binary) that runs on the background. Logging features could be improved (see Networklog for details and how to save data asynchronously) and customised depending on your requirements.

#Networklog APK. 

Traffic monitor app exploiting iptables nflog feature. It collects mobile traffic at IP level. The current version is a customised extention of: __ADD_URL__

It has to be launched by the user for the first time and then modify the app settings to launch it automatically on boot. Data output is written by itself on /sdcard/networklog.txt (can be customized).

It also makes sure that required processes (e.g. iptables flags) are set up correctly.

#Logger Binary

Binary (c) that runs in the background and reads UDP packets from RILAnalyzr and saves them on the SD Card.

Build using Android NDK.

#Building and Instalation:

__IMPORTANT__: __Requires rooted devices.__

Install Android SDK and NDK.

Create and import projects separately on Eclipse.

Remove Samsung Service Mode:

$adb shell mount -o rw,remount /system/
$adb shell rm /system/...
$adb shell mount -o ro,remount /system/


Build logger process using Android NDK (with the right target). It is required for storing RNC events on /sdcard/. To install, move the binary to /system/ so it is automatically launched on boot:

$adb shell mount -o rw,remount /system/
$adb push SOURCE_LOGGER ...
$adb shell mount -o ro,remount /system/


Use ADB to put send APKs to mobile handset: 

$adb shell mount -o rw,remount /system/
$adb push source_rilanalyzer_apk /system/...
$adb push source_networklog_apk /
$adb shell mount -o ro,remount /system/

Reboot handset:

$adb reboot

Launch Networklog manually. RILAnalyzer and logger binary should be automatically launched on boot. To stop and remove all the logging capabilities, remove the files manually (mount filesystem with the right permisions accordingly):

$adb shell rm PATH_TO_APK/BINARY

#Warning

The logging processes are very CPU and memory intense. The battery life of the handset can be negatively affected. The main problem is the lack of firmware and OS support. RIL events have to be polled directly from the OS.

For further details, please, do not hesitate to contact us.
