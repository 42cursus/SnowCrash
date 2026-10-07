# Objective

As `level02`, the goal is to exploit a vulnerability to gain `flag02`'s privileges and read the flag, which is the password for `level03`.

The flag is gained through the command `getflag`, run as `flag02`.

```sh
level02@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```


# Content of home

The home folder contains an interesting file, `level02.pcap`.

```sh
level02@SnowCrash:~$ pwd
/home/user/level02

level02@SnowCrash:~$ ll
total 24
dr-x------ 1 level02 level02  120 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level02 level02  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level02 level02 3518 Aug 30  2015 .bashrc*
----r--r-- 1 flag02  level02 8302 Aug 30  2015 level02.pcap
-r-x------ 1 level02 level02  675 Apr  3  2012 .profile*
```


## pcap files

A PCAP (Packet Capture) file is the industry-standard file format used to store and analyze computer network traffic. It captures raw, live packet data directly from a network interface card (OSI layers 2 through 7) and saves it with precise timestamps for later inspection.

> Certainly, this is promising!

# Resolution

Let us transfer the file on the host machine, in order to open with with a proper software.

First, let us make it readable by anyone.

```sh
level02@SnowCrash:~$ ll level02.pcap 
----r--r-- 1 flag02 level02 8302 Aug 30  2015 level02.pcap

level02@SnowCrash:~$ cat level02.pcap > file_we_own.pcap
```

Then let us download it on the host machine.

```sh
sh-5.3$ scp -P 4242 level02@localhost:/home/user/level02/file_we_own.pcap .
```

Finally, let us open it with `Wireshark` in order to read the TCP data transfer.

## Data transferred by the server

```
00000000  ff fd 25                                           ..%
00000003  ff fb 26 ff fd 18 ff fd  20 ff fd 23 ff fd 27 ff   ..&.....  ..#..'.
00000013  fd 24                                              .$
00000015  ff fa 20 01 ff f0 ff fa  23 01 ff f0 ff fa 27 01   .. ..... #.....'.
00000025  ff f0 ff fa 18 01 ff f0                            ........ 
0000002D  ff fb 03 ff fd 01 ff fd  22 ff fd 1f ff fb 05 ff   ........ ".......
0000003D  fd 21                                              .!
0000003F  ff fa 22 01 03 ff f0                               .."....
00000046  ff fa 21 03 ff f0 ff fb  01 ff fd 00 ff fe 22      ..!..... ......"
00000055  ff fa 22 03 03 e2 03 04  82 0f 07 e2 1c 08 82 04   .."..... ........
00000065  09 c2 1a 0a 82 7f 0b 82  15 0f 82 11 10 82 13 11   ........ ........
00000075  82 ff ff 12 82 ff ff ff  f0                        ........ .
0000007E  0d 0a 4c 69 6e 75 78 20  32 2e 36 2e 33 38 2d 38   ..Linux  2.6.38-8
0000008E  2d 67 65 6e 65 72 69 63  2d 70 61 65 20 28 3a 3a   -generic -pae (::
0000009E  66 66 66 66 3a 31 30 2e  31 2e 31 2e 32 29 20 28   ffff:10. 1.1.2) (
000000AE  70 74 73 2f 31 30 29 0d  0a 0a 01 00 77 77 77 62   pts/10). ....wwwb
000000BE  75 67 73 20 6c 6f 67 69  6e 3a 20                  ugs logi n: 
000000C9  00 6c                                              .l
000000CB  00 65                                              .e
000000CD  00 76                                              .v
000000CF  00 65                                              .e
000000D1  00 6c                                              .l
000000D3  00 58                                              .X
000000D5  01                                                 .
000000D6  00 0d 0a 50 61 73 73 77  6f 72 64 3a 20            ...Passw ord: 
000000E3  00 0d 0a                                           ...
000000E6  01                                                 .
000000E7  00 0d 0a 4c 6f 67 69 6e  20 69 6e 63 6f 72 72 65   ...Login  incorre
000000F7  63 74 0d 0a 77 77 77 62  75 67 73 20 6c 6f 67 69   ct..wwwb ugs logi
00000107  6e 3a 20                                           n: 
```

We can clearly see that the server asked for a login and the password.

### Data transferred by the client

```
00000000  ff fc 25                                           ..%
00000003  ff fe 26 ff fb 18 ff fb  20 ff fb 23 ff fb 27 ff   ..&.....  ..#..'.
00000013  fc 24                                              .$
00000015  ff fa 20 00 33 38 34 30  30 2c 33 38 34 30 30 ff   .. .3840 0,38400.
00000025  f0 ff fa 23 00 53 6f 64  61 43 61 6e 3a 30 ff f0   ...#.Sod aCan:0..
00000035  ff fa 27 00 00 44 49 53  50 4c 41 59 01 53 6f 64   ..'..DIS PLAY.Sod
00000045  61 43 61 6e 3a 30 ff f0  ff fa 18 00 78 74 65 72   aCan:0.. ....xter
00000055  6d ff f0                                           m..
00000058  ff fd 03 ff fc 01 ff fb  22 ff fa 22 03 01 00 00   ........ ".."....
00000068  03 62 03 04 02 0f 05 00  00 07 62 1c 08 02 04 09   .b...... ..b.....
00000078  42 1a 0a 02 7f 0b 02 15  0f 02 11 10 02 13 11 02   B....... ........
00000088  ff ff 12 02 ff ff ff f0  ff fb 1f ff fa 1f 00 b1   ........ ........
00000098  00 31 ff f0 ff fd 05 ff  fb 21                     .1...... .!
000000A2  ff fa 22 01 07 ff f0                               .."....
000000A9  ff fd 01 ff fb 00 ff fc  22                        ........ "
000000B2  6c                                                 l
000000B3  65                                                 e
000000B4  76                                                 v
000000B5  65                                                 e
000000B6  6c                                                 l
000000B7  58                                                 X
000000B8  0d                                                 .
000000B9  66                                                 f
000000BA  74                                                 t
000000BB  5f                                                 _
000000BC  77                                                 w
000000BD  61                                                 a
000000BE  6e                                                 n
000000BF  64                                                 d
000000C0  72                                                 r
000000C1  7f                                                 .
000000C2  7f                                                 .
000000C3  7f                                                 .
000000C4  4e                                                 N
000000C5  44                                                 D
000000C6  52                                                 R
000000C7  65                                                 e
000000C8  6c                                                 l
000000C9  7f                                                 .
000000CA  4c                                                 L
000000CB  30                                                 0
000000CC  4c                                                 L
000000CD  0d                                                 .
```

It seems that the client started by typing something related to the level, then proceeded on typing its password. Thankfully, the data stream wasn't encrypted!

Having in mind that the character 0x7f is `DEL`, we can reconstitute the client's input:

`ft_wandr \DEL \DEL \DEL NDRel \DEL L0L \ENTER` which translates to : `ft_waNDReL0L`.

Let us try !

```sh
level02@SnowCrash:~$ su - flag02
Password: # ft_waNDReL0L
Don't forget to launch getflag !
flag02@SnowCrash:~$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq
```