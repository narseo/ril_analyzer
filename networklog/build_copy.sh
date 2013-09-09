rm -rf obj/
rm -rf res/raw/*.zip
rm -rf libs/
cd jni/
ndk-build 
cd ..
cp libs/armeabi-v7a/iptables libs/armeabi-v7a/iptables_armv7
cp libs/armeabi-v7a/nflog libs/armeabi-v7a/nflog_armv7
cp libs/armeabi-v7a/grep libs/armeabi-v7a/grep_armv7
cp libs/armeabi/iptables libs/armeabi/iptables_armv5
cp libs/armeabi/nflog libs/armeabi/nflog_armv5
cp libs/armeabi/grep libs/armeabi/grep_armv5
cp libs/mips/iptables libs/mips/iptables_mips
cp libs/mips/nflog libs/mips/nflog_mips
cp libs/mips/grep libs/mips/grep_mips
cp libs/x86/iptables libs/x86/iptables_x86
cp libs/x86/nflog libs/x86/nflog_x86
cp libs/x86/grep libs/x86/grep_x86
#Generate zip files
zip -r res/raw/iptables_armv7.zip libs/armeabi-v7a/iptables_armv7
zip -r res/raw/nflog_armv7.zip libs/armeabi-v7a/nflog_armv7
zip -r res/raw/grep_armv7.zip libs/armeabi-v7a/grep_armv7

zip -r res/raw/iptables_armv5.zip libs/armeabi/iptables_armv5
zip -r res/raw/nflog_armv5.zip libs/armeabi/nflog_armv5
zip -r res/raw/grep_armv5.zip libs/armeabi/grep_armv5

zip -r res/raw/iptables_mips.zip libs/mips/iptables_mips
zip -r res/raw/nflog_mips.zip libs/mips/nflog_mips
zip -r res/raw/grep_mips.zip libs/mips/grep_mips

zip -r res/raw/iptables_x86.zip libs/x86/iptables_x86
zip -r res/raw/nflog_x86.zip libs/x86/nflog_x86
zip -r res/raw/grep_x86.zip libs/x86/grep_x86

ant -f build.xml clean debug -Dsdk.dir=/Applications/android-sdk-mac_x86/


#ant -f build.xml clean -Dsdk.dir=/Applications/android-sdk-mac_x86/
