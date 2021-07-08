using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

/*
创建日期:2020年

作者QQ:5115147

简介:Rtmp嗅探器

如需更多功能或软件定制及开发请联系作者QQ:5115147 或 960596621

使用注意事项:

需要先安装npcap驱动

 */

namespace RtmpSniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            //开启网卡监听
            LibPcapLiveDevice device = null;

            //WinPcap驱动
            //var devices = LibPcapLiveDeviceList.Instance;

            //Npcap驱动
            var devices = NpcapDeviceList.Instance;

            bool exitDeviceLoop = false;

            foreach (var dev in devices)
            {
                if (dev.Addresses.Count > 0)
                {
                    foreach (var address in dev.Addresses)
                    {
                        if (address.Addr.type == Sockaddr.AddressTypes.AF_INET_AF_INET6 && address.Addr.sa_family == 2)
                        {
                            string ip = address.Addr.ipAddress.ToString();

                            //不拦截内网网关
                            if (ip == "192.168.137.1")
                            {
                                continue;
                            }

                            device = dev;

                            exitDeviceLoop = true;

                            Console.WriteLine($"准备监听网卡:{dev.Interface.FriendlyName} IP地址:{ip}");

                            break;
                        }
                    }

                    if (exitDeviceLoop)
                    {
                        break;
                    }
                }
            }

            if (device != null)
            {
                //Register our handler function to the 'packet arrival' event
                device.OnPacketArrival += Device_OnPacketArrival;

                // Open the device for capturing
                int readTimeoutMilliseconds = 100000;

                if (device is NpcapDevice)
                {
                    var npcap = device as NpcapDevice;

                    npcap.Open(OpenFlags.NoCaptureLocal, readTimeoutMilliseconds);//| OpenFlags.Promiscuous
                }
                else if (device is LibPcapLiveDevice)
                {
                    var livePcapDevice = device as LibPcapLiveDevice;

                    livePcapDevice.Open(DeviceMode.Normal, readTimeoutMilliseconds);//DeviceMode.Promiscuous
                }
                else
                {
                    Console.WriteLine("unknown device type of " + device.GetType().ToString());
                }

                //tcpdump filter to capture only TCP/IP packets
                //tcp port 80 http
                //tcp port 1935 rtmp
                //udp port 53 dns

                //源地址为局域网地址 目标端口1935
                device.Filter = "tcp dst port 1935 and len>0";

                // Start the capturing process
                device.StartCapture();

                Console.WriteLine("开始进行网络监听...");
            }
            else
            {
                Console.WriteLine("未发现可上网网卡");
            }

            Console.ReadLine();

            if (device != null)
            {
                device.StopCapture();

                device.Close();

                device.OnPacketArrival -= Device_OnPacketArrival;

                device = null;
            }
        }

        /// <summary>
        /// connect
        /// </summary>
        public static string connectFlag = "\u0002\0\aconnect";

        /// <summary>
        /// tcUrl
        /// </summary>
        public static string tcUrlFlag = "\0\u0005tcUrl\u0002";

        /// <summary>
        /// play
        /// </summary>
        public static string playFlag = "\u0002\0\u0004play";

        /// <summary>
        /// 多线程锁
        /// </summary>
        public static object LockObj = new object();

        /// <summary>
        /// ip:port,rtmpUrl
        /// </summary>
        public static Dictionary<string, string> dic = new Dictionary<string, string>();

        /// <summary>
        /// ip:port,SequenceNumber
        /// </summary>
        public static Dictionary<string, int> SequenceDic = new Dictionary<string, int>();

        public static void Device_OnPacketArrival(object sender, SharpPcap.CaptureEventArgs e)
        {
            var date = e.Packet.Timeval.Date.ToLocalTime();

            if (e.Packet.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            {
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

                //解析tcp数据
                var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();

                if (tcpPacket != null && tcpPacket.PayloadData.Length > 0)
                {
                    var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;

                    IPAddress srcIp = ipPacket.SourceAddress;

                    IPAddress dstIp = ipPacket.DestinationAddress;

                    int srcPort = tcpPacket.SourcePort;

                    int dstPort = tcpPacket.DestinationPort;

                    //Console.WriteLine($"{date.ToString("yyyy-MM-dd HH:mm:ss.fff")} {srcIp}:{srcPort} -> {dstIp}:{dstPort} Length:{tcpPacket.PayloadData.Length}");

                    string key = $"{srcIp}:{srcPort}";

                    //File.WriteAllBytes($"{tcpPacket.SequenceNumber}.dat", tcpPacket.PayloadData);

                    byte[] bytes = tcpPacket.PayloadData;

                    string text = Encoding.ASCII.GetString(bytes);

                    if (text.Contains(connectFlag) && text.Contains(tcUrlFlag) && text.Contains("rtmp://"))
                    {
                        string rtmpUrl = string.Empty;

                        text = text.Substring(text.IndexOf(tcUrlFlag));

                        text = text.Remove(0, tcUrlFlag.Length);

                        if (text.Length > 2)
                        {
                            char[] chars = new char[] { text[0], text[1] };

                            byte[] numbytes = Encoding.ASCII.GetBytes(chars);

                            int len = (numbytes[0] << 8) | numbytes[1];

                            if (text.Length >= (len + 2))
                            {
                                text = text.Remove(0, 2);

                                rtmpUrl = text.Substring(0, len);

                                dic[key] = rtmpUrl;

                                //Console.WriteLine($"获取到connect:{rtmpUrl}");
                            }
                        }

                        //if (string.IsNullOrEmpty(rtmpUrl))
                        //{
                        //Console.WriteLine($"获取connect失败:{key}");

                        //File.WriteAllBytes($"{tcpPacket.SequenceNumber}_connect.dat", tcpPacket.PayloadData);
                        //}
                    }
                    else if (text.Contains(playFlag))
                    {
                        string play = string.Empty;

                        text = text.Substring(text.IndexOf(playFlag));

                        text = text.Remove(0, playFlag.Length);

                        if (text[0] == '\0' && text[9] == '\u0005' && text[10] == '\u0002')
                        {
                            text = text.Remove(0, 11);

                            if (text.Length > 2)
                            {
                                char[] chars = new char[] { text[0], text[1] };

                                byte[] numbytes = Encoding.ASCII.GetBytes(chars);

                                int len = (numbytes[0] << 8) | numbytes[1];

                                if (text.Length >= (len + 2))
                                {
                                    //File.WriteAllText($"{tcpPacket.SequenceNumber}_play.txt", text);

                                    text = text.Remove(0, 2);

                                    play = text.Substring(0, len);

                                    int index1 = play.IndexOf('?');

                                    int index2 = play.LastIndexOf('?');

                                    //如果存在2个问号
                                    if (index1 != index2)
                                    {
                                        play = text.Substring(0, len + 1);
                                    }

                                    string front = play.Substring(0, play.IndexOf('?'));

                                    string end = play.Substring(play.IndexOf('?'));

                                    end = end.Replace("?", "");

                                    play = front + "?" + end;

                                    //Console.WriteLine($"获取到play:{play}");
                                }
                                else
                                {
                                    //需要读取下一个数据包 SequenceNumber,长度
                                    text = text.Remove(0, 2);

                                    int leftTextLen = len - text.Length;

                                    SequenceDic.Add($"{key},{tcpPacket.SequenceNumber},{text.Substring(0)}", leftTextLen);
                                }
                            }

                            //if (string.IsNullOrEmpty(play))
                            //{
                            //Console.WriteLine($"获取play失败:{key}");

                            //File.WriteAllBytes($"{tcpPacket.SequenceNumber}_play.dat", tcpPacket.PayloadData);
                            // }

                            // if (!dic.ContainsKey(key))
                            // {
                            //Console.WriteLine($"connect还未获取到:{key}");
                            //}

                            if (dic.ContainsKey(key) && (!string.IsNullOrEmpty(play)))
                            {
                                string fullUrl = $"{dic[key]}/{play}";

                                Console.WriteLine($"{fullUrl}");

                                dic.Remove(key);
                            }
                            //else
                            //{
                            //Console.WriteLine($"获取Rtmp地址失败:{key}");
                            // }
                        }
                    }
                    else
                    {
                        lock (LockObj)
                        {
                            string delKey = string.Empty;

                            //如果是当前SequenceNumber
                            foreach (var item in SequenceDic)
                            {
                                string[] strArr = item.Key.Split(new char[] { ',' });

                                uint number = uint.Parse(strArr[1]);

                                if (strArr[0] == key && tcpPacket.SequenceNumber > number)
                                {
                                    delKey = item.Key;

                                    //File.WriteAllBytes($"{tcpPacket.SequenceNumber}_play2.dat", tcpPacket.PayloadData);

                                    string playUrl = $"{strArr[2]}{text.Substring(0, item.Value)}";

                                    byte[] data = Encoding.ASCII.GetBytes(new char[] { text[0] });

                                    if (data[0] == 0x3f || data[0] == 0xc8)
                                    {
                                        playUrl = $"{strArr[2]}{text.Substring(1, item.Value)}";
                                    }

                                    string fullUrl = $"{dic[key]}/{playUrl}";

                                    Console.WriteLine($"{fullUrl}");

                                    dic.Remove(key);

                                    break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(delKey))
                            {
                                SequenceDic.Remove(delKey);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// 删除不可见字符
        /// </summary>
        /// <param name="sourceString">原始字符</param>
        /// <returns>删除后结果</returns>
        public static string DeleteUnVisibleChar(string sourceString)
        {
            StringBuilder sBuilder = new StringBuilder(131);

            for (int i = 0; i < sourceString.Length; i++)
            {
                int Unicode = sourceString[i];

                if (Unicode >= 16)
                {
                    sBuilder.Append(sourceString[i].ToString());
                }
            }

            return sBuilder.ToString();
        }
    }
}
