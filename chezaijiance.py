# coding:utf-8
import shutil
from datetime import datetime
from datetime import timedelta
import time
from scapy.all import *
import re
import os
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
from pyasn1.codec.ber import encoder
from pysnmp.proto import api


class U_package:  # 插入U盘自导入
    def get_udisk(self):  # 当U盘插入时此文件存在
        a = os.path.exists("/proc/scsi/usb-storage")
        return a

    def find_copyfile(self, file_address):  # 找到要copy的pcap文件
        items = os.listdir(file_address)
        filelist = []
        for names in items:
            if names.endswith(".pcap"):
                filelist.append(names)
        return filelist

    def is_success_copy(self, copylist, copylist_later):
        for copy_file in copylist:
            if copy_file in copylist_later:
                pass
            else:
                break
        else:  # 如果每一个文件都在，说明copy完成，一直响直到占用解除，copy没有完成不会响
            print("success copy")
            while True:
                try:
                    have_udisk_list = os.listdir("/media/bjtu")
                    for i in have_udisk_list:
                        os.system("umount -f /media/bjtu/" + str(i))
                except Exception as err:
                    print(err)
                os.system("/usr/bin/beep -f 900 -l 300")
                check_udisk = self.get_udisk()
                if check_udisk == False:
                    break

    def find_copy_later_file(self, find_path_copy_later):
        file_name = []
        for i in find_path_copy_later:
            file_name_one = os.listdir(i)
            for j in file_name_one:
                file_name.append(j)
        return file_name

    def main_u_package(self):  # 将需要copy的文件复制到U盘里，传输完成时蜂鸣器响
        find_path_copy_later = []
        print("start package")
        while True:
            udisk = self.get_udisk()
            if udisk == True:
                have_udisk_list = os.listdir("/media/bjtu")
                print(have_udisk_list)
                try:
                    for u_disk_name in have_udisk_list:  
                        print("bainli")
                        copylist = self.find_copyfile("/home/bjtu/pcapfiles/")
                        for i in copylist:
                            copylist_date = str(i[0:10])
                            u_disk_home = str("/media/bjtu/" + str(u_disk_name) + "/" + copylist_date)
                            find_path_copy_later.append(u_disk_home)
                            if not os.path.exists(u_disk_home):
                                os.makedirs(u_disk_home)
                            shutil.copyfile("/home/bjtu/pcapfiles/" + str(i), u_disk_home + "/" + str(i))
                            os.system("/usr/bin/beep -f 100 -l 100")
                    find_path_copy_later_set = set(find_path_copy_later)
                    copylist_later = self.find_copy_later_file(find_path_copy_later_set)  
                    self.is_success_copy(copylist,
                                         copylist_later)  # 检测是否复制完成，完成会一直响，直到U盘拔下如果没有copy成功不会响。只会调用一次，里面有个while循环。

                    logging.debug("成功读取数据")
                except Exception as err:
                    print(err)
            else:  # 说明拔出去了，下次插入进来还是要copy
                find_path_copy_later = []
                have_udisk_list = os.listdir("/media/bjtu")
                if len(have_udisk_list) != 0:
                    print(have_udisk_list)
                    for i in have_udisk_list:
                        os.system("rm -rf" + " /media/bjtu/" + i + "\n")
                        print("del success")
            time.sleep(5)


def get_pcap():  # 抓包
    global pcap_package
    sniff(filter=filter_ip, prn=lambda x: pcap_package.append(x))  # filter=filter_ip,


def get_pcap1():  # 抓包
    global pcap_package1
    sniff(filter=filter_ip1, prn=lambda x: pcap_package1.append(x))


def save_pcap_void():
    global save_package
    global pcap_package
    global pcap_package1
    global save_name
    global save_now_flag
    save_name_time = save_name
    save_name_time = save_name_time.replace(":", "：")
    save_package = pcap_package + pcap_package1
    wrpcap("/home/bjtu/pcapfiles/" + str(save_name_time) + ".pcap", save_package)
    if save_now_flag:
        save_package = []
        logging.debug(str(save_name_time) + " now time pcap save")
    else:
        pcap_package = []
        pcap_package1 = []
        save_package = []
        save_name = (datetime.now()).strftime("%Y-%m-%d %H:%M")


def ntp_tau_same():  # 时钟同步
    global time_same_flag
    ntpdate_ip = '172.16.6.4'
    os.system("ntpdate " + ntpdate_ip)
    time_same_flag = 1


def delete_file_void():  # 删除七天前的文件
    global bool_get_package
    global copy_list_ago
    copy_list_now = u_package.find_copyfile("/home/bjtu/pcapfiles/")
    copy_list_date = list(set([i[0:10] for i in copy_list_now]))
    if len(copy_list_date) > 7:
        del_copy_list_date = sorted(copy_list_date)[0]
        delete_file = [i for i in copy_list_now if i[0:10] == del_copy_list_date]
        for i in delete_file:
            u_disk_home = "/home/bjtu/pcapfiles/" + str(i)
            os.remove(u_disk_home)
            logging.debug("删除7天前的文件")


def watchdog():
    global bool_get_package  # 用来判断是不是在抓包即可，喂狗操作在循环里，执行喂狗说明循环一直在执行
    global is_first_watchdog
    if is_first_watchdog:
        try:
            os.system("cd /home/bjtu/watchdog/module\n" + "insmod acpi_call.ko\n")
            is_first_watchdog = False
        except:
            pass
    if bool_get_package:  # 只监测抓包
        print('weigou')
        os.system(
            "cd /home/bjtu/watchdog/ismmpSDK_lib_demo\n" + "./ismmplusSDK_lib_demo --wdt=0 --wdt-timer=" + watchdog_time + " --wdt-timer-unit=1\n")
        logging.debug("执行一次喂狗操作")


def get_package_work():
    global first_package_count
    global bool_get_package
    now_package_count = len(u_package.find_copyfile("/home/bjtu/pcapfiles/"))
    if now_package_count != first_package_count:
        bool_get_package = True
    else:
        bool_get_package = False
    first_package_count = now_package_count


def save_pack_work():  # 定时存储数据包
    global save_pcap_count
    global save_now_pcap_count
    global save_now_flag
    global time_same_flag
    save_pcap_count = save_pcap_count + 1
    save_now_pcap_count = save_now_pcap_count + 1
    if save_pcap_count >= 600 and time_same_flag == 1:
        save_now_flag = False
        save_pcap_void()
        save_pcap_count = 0
        print('cunbao')
    if save_pcap_count <= 590 and save_now_pcap_count >= 10 and time_same_flag == 1:
        save_now_flag = True
        save_pcap_void()
        save_now_pcap_count = 0
        print('save now time pcap')
    save_pack_timer_later_time = 1
    save_pack_timer = threading.Timer(save_pack_timer_later_time, save_pack_work)
    save_pack_timer.setDaemon(True)
    save_pack_timer.start()


def snmp_msg_send():
    try:
        verID = api.protoVersion2c
        pMod = api.protoModules[verID]

        trapPDU = pMod.TrapPDU()
        pMod.apiTrapPDU.setDefaults(trapPDU)
        now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Traps have quite different semantics among proto versions
        if verID == api.protoVersion2c:
            var = []
            oid = (1, 3, 6, 1, 4, 1, 3902, 2, 2, 4)
            val = pMod.OctetString("2001")
            var.append((oid, val))
            oid = (1, 3, 6, 1, 4, 1, 3902, 2, 2, 5)
            val = pMod.OctetString("60")
            var.append((oid, val))
            oid = (1, 3, 6, 1, 4, 1, 3902, 2, 2, 6)
            val = pMod.OctetString(now_time)
            var.append((oid, val))
            pMod.apiTrapPDU.setVarBinds(trapPDU, var)

        trapMsg = pMod.Message()
        pMod.apiMessage.setDefaults(trapMsg)
        pMod.apiMessage.setCommunity(trapMsg, 'Beijing JiaoTong University')
        pMod.apiMessage.setPDU(trapMsg, trapPDU)

        transportDispatcher = AsynsockDispatcher()
        transportDispatcher.registerTransport(udp.domainName, udp.UdpSocketTransport().openClientMode())
        transportDispatcher.sendMessage(encoder.encode(trapMsg), udp.domainName,
                                        (ntp_ip2, 162))  # 为对应trapserver的IP地址。
        transportDispatcher.runDispatcher()
        transportDispatcher.closeDispatcher()
    except:
        logging.debug('snmp send fail!')
        print('snmp send fail')


def send_snmp_package():        # 发snmp包
    global snmp_heart_count
    snmp_heart_count = snmp_heart_count + 1
    if snmp_heart_count > 60:
        snmp_msg_send()
        print('snmp send')
        snmp_heart_count = 0
    snmp_send_step_time = 1
    snmp_send_timer = threading.Timer(snmp_send_step_time, send_snmp_package)
    snmp_send_timer.setDaemon(True)
    snmp_send_timer.start()


def heart_message():  # 发送心跳信息包
    global time_same_count
    global delete_file_count
    global is_first_heart
    global ntp_time_same_count
    global work_flag_count
    global save_name
    time_same_count = time_same_count + 1
    delete_file_count = delete_file_count + 1
    ntp_time_same_count = ntp_time_same_count + 1
    work_flag_count = work_flag_count + 1
    if is_first_heart:  # 开始的时候需要先进行时钟同步
        ntp_tau_same()
        save_name = (datetime.now()).strftime("%Y-%m-%d %H:%M")
        watchdog()
        is_first_heart = False
    if time_same_count > 90:    # 进行喂狗操作
        watchdog()
        time_same_count = 0
    if delete_file_count > 10:  # 检查删除文件
        delete_file_void()
        print('delete check')
        delete_file_count = 0
    if ntp_time_same_count > 5:   # 时钟同步
        ntp_tau_same()
        ntp_time_same_count = 0
    if work_flag_count > 1800:    # 检查抓包是否进行
        get_package_work()
        work_flag_count = 0
    heart_message_timer_later_time = 1
    heart_message_timer = threading.Timer(heart_message_timer_later_time, heart_message)
    heart_message_timer.setDaemon(True)
    heart_message_timer.start()


if __name__ == '__main__':
    ntp_ip1 = '10.108.2.1'      # TUA package ip
    ntp_ip2 = "10.108.3.1"	    # TAU communication ip

    vobc_port1 = ["50001", "50002", "50003"]
    vobc_port2 = ["50001", "50002", "50003"]
    VOBC_ip1 = "103.10.8.2"          # VOBC8-RedIP1
    VOBC_ip2 = "103.11.8.2"          # VOBC8-RedIP2

    grd_ip_list = ["103.24.11.20",  # CI_XJCBHZL 1
                   "103.24.21.20",  # CI_CGZ     2
                   "103.24.29.20",  # CI_CQ      3
                   "103.24.35.20",  # CI_SCX    13
                   "103.24.90.20",  # CI_DEP    14
                   "103.24.94.20",  # CI_TEP    15
                   "103.24.11.2",   # ZC_XJCBHZL 4
                   "103.24.21.2",   # ZC_CGZ     5
                   "103.24.29.2",   # ZC_CQ      6
                   "103.24.35.2",   # ZC_SCX    16
                   "103.24.90.2",   # ZC_DEP    17
                   "103.16.11.54",  # ATS_1_XJCBHZL 7
                   "103.16.11.56",  # ATS_2_XJCBHZL 8
                   "103.16.21.54",  # ATS_1_CGZ  9
                   "103.16.21.56",  # ATS_2_CGZ 10
                   "103.16.29.54",  # ATS_1_CQ  11
                   "103.16.29.56",  # ATS_2_CQ  12
                   "103.16.90.54",  # ATS_1_DEP 18
                   "103.16.90.56",  # ATS_2_DEP 19
                   "103.16.94.54",  # ATS_1_TEP 20
                   "103.16.94.56"]  # ATS_2_TEP 21

    grd_port_list = [["50001", "50002", "50003"],  # 1
                     ["50001", "50002", "50003"],  # 2
                     ["50001", "50002", "50003"],  # 3
                     ["50001", "50002", "50003"],  # 4
                     ["50001", "50002", "50003"],  # 5
                     ["50001", "50002", "50003"],  # 6
                     ["50001", "50002", "50003"],  # 7
                     ["50001", "50002", "50003"],  # 8
                     ["50001", "50002", "50003"],  # 9
                     ["50001", "50002", "50003"],  # 10
                     ["50001", "50002", "50003"],  # 11
                     ["50001", "50002", "50003"],  # 12
                     ["50001", "50002", "50003"],  # 13
                     ["50001", "50002", "50003"],  # 14
                     ["50001", "50002", "50003"],  # 15
                     ["50001", "50002", "50003"],  # 16
                     ["50001", "50002", "50003"],  # 17
                     ["50001", "50002", "50003"],  # 18
                     ["50001", "50002", "50003"],  # 19
                     ["50001", "50002", "50003"],  # 20
                     ["50001", "50002", "50003"]]  # 21
    filter1 = []
    filter2 = []
    filter3 = []
    filter4 = []
    for i in range(len(grd_ip_list)):
        filter1.append("((src port " + grd_port_list[i][0] + " or src port " + grd_port_list[i][1] + " or src port " +
                       grd_port_list[i][2] + ") and src host " + grd_ip_list[i] + " and (dst port " + vobc_port1[0] +
                       " or dst port " + vobc_port1[1] + " or dst port " + vobc_port1[2] + ") and dst host " +
                       VOBC_ip1 + " )")
        filter2.append("((src port " + vobc_port1[0] + " or src port " + vobc_port1[1] + " or src port " + vobc_port1[2] +
                       ") and src host " + VOBC_ip1 + " and (dst port " + grd_port_list[i][0] + " or dst port " +
                       grd_port_list[i][1] + " or dst port " + grd_port_list[i][2] + ") and dst host " +
                       grd_ip_list[i] + " )")
        filter3.append("((src port " + grd_port_list[i][0] + " or src port " + grd_port_list[i][1] + " or src port " +
                       grd_port_list[i][2] + ") and src host " + grd_ip_list[i] + " and (dst port " + vobc_port2[0] +
                       " or dst port " + vobc_port2[1] + " or dst port " + vobc_port2[2] + ") and dst host " +
                       VOBC_ip2 + " )")
        filter4.append("((src port " + vobc_port2[0] + " or src port " + vobc_port2[1] + " or src port " + vobc_port2[2] +
                       ") and src host " + VOBC_ip2 + " and (dst port " + grd_port_list[i][0] + " or dst port " +
                       grd_port_list[i][1] + " or dst port " + grd_port_list[i][2] + ") and dst host " +
                       grd_ip_list[i] + " )")
    filter1.extend(filter2)
    # filter1.extend(filter3)
    filter3.extend(filter4)
    filter_ip = " or ".join(filter1)
    filter_ip1 = " or ".join(filter3)

    print(filter_ip)
    print(filter_ip1)

    logging.basicConfig(filename="C:\Dropbox\Code\ML\Study\my.log", level=logging.DEBUG,
                        format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')
    logging.debug("start chezaijiance.py")
    u_package = U_package()

    save_package = []
    pcap_package = []
    get_pcap = threading.Thread(target=get_pcap)  # 开抓包的线程一直抓包
    get_pcap.daemon = True
    get_pcap.start()

    pcap_package1 = []
    get_pcap1 = threading.Thread(target=get_pcap1)  # 开抓包的线程一直抓包
    get_pcap1.daemon = True
    get_pcap1.start()

    if not os.path.exists("/home/bjtu/pcapfiles/"):
        os.makedirs("/home/bjtu/pcapfiles/")
        os.system("sudo chmod a-w /home/bjtu/pcapfiles/")

    first_package_count = len(u_package.find_copyfile("/home/bjtu/pcapfiles/"))
    try:
        os.system("cd /home/bjtu/beep-master\n"+"modprobe pcspkr\n")
        os.system("cd /home/bjtu/beep-master\n"+"/usr/bin/beep -f 3000 -l 100\n")
        os.system("sudo chmod 777 /etc/modprobe.d/blacklist.conf")
        print("OK")
    except:
        pass
    
    time_same_flag = 0
    save_now_flag = True
    time_same_count = 0
    ntp_time_same_count = 0
    delete_file_count = 0
    save_pcap_count = 0
    save_now_pcap_count = 0
    snmp_heart_count = 0
    work_flag_count = 0
    is_first_watchdog = True
    bool_get_package = True
    is_first_heart = True
    copy_list_ago = []
    watchdog_time = "10"  # 10min不重启即认为正常

    heart_message()
    time.sleep(1)
    save_pack_work()
    send_snmp_package()

    is_copy = True  # 是不是要copy
    u_package.main_u_package()
