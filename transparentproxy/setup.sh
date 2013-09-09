#************************************************************************
#* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
#* narseo@gmail.com                                                     *
#*************************************************************************/

adb shell openvpn --mktun --dev tun1
adb shell ip link set tun1 up
adb shell ip addr add 10.0.1.1/24 dev tun1
#This doesn't seem to work from adb shell, but once on the shell
#it does. In any case, enabling forwarding seems to do not
#be necessary (it was if we were using iptables)
adb shell echo 1 > /proc/sys/net/ipv4/ip_forward
adb shell ip route change default via 10.0.1.1 dev tun1
adb shell ip route del 10.0.1.1
adb shell ip route del 10.0.1.1
#Check that there isn't anything wrong on the ip routes
adb shell ip route sh
