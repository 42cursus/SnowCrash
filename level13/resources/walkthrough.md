# Objective

As `level13`, the goal is to exploit a vulnerability to gain `flag13`'s privileges and read the flag, which is the password for `level14`.

The flag is gained through the command `getflag`, run as `flag13`.

```sh
level13@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

```sh
level13@SnowCrash:~$ pwd
/home/user/level13

level13@SnowCrash:~$ ll
total 20
dr-x------ 1 level13 level13  120 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level13 level13  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level13 level13 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x 1 flag13  level13 7303 Aug 30  2015 level13*
-r-x------ 1 level13 level13  675 Apr  3  2012 .profile*
```

### File type

```sh
level13@SnowCrash:~$ file level13 
level13: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xde91cfbf70ca6632d7e4122f8210985dea778605, not stripped
```

### Behavior

```sh
level13@SnowCrash:~$ ./level13 
UID 2013 started us but we we expect 4242
```

# Resolution

The program expects us to be 4242. How does it know?

```sh
level13@SnowCrash:~$ ltrace ./level13 
__libc_start_main(0x804858c, 1, 0xbffff864, 0x80485f0, 0x8048660 <unfinished ...>
getuid()                                                                                                      = 2013
getuid()                                                                                                      = 2013
printf("UID %d started us but we we expe"..., 2013UID 2013 started us but we we expect 4242
)                                                           = 42
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

It calls `getuid` twice and compares the result to 4242 before printing anything useful. Since the binary is setuid `flag13` but checks the *real* UID rather than the effective one, simply running it as `level13` fails the check — but we can still intercept the call with a debugger and force its return value to 4242.

```sh
level13@SnowCrash:~$   gdb -nx -q -batch \
>     -ex 'set confirm off' \
>     -ex 'break getuid' \
>     -ex 'run' \
>     -ex 'return (unsigned int)4242' -ex 'continue' \
>     ./level13
Breakpoint 1 at 0x8048380

Breakpoint 1, 0xb7ee4cc0 in getuid () from /lib/i386-linux-gnu/libc.so.6
your token is 2A31L79asukciNyi8uppkEuSx
[Inferior 1 (process 5566) exited with code 050]
```

Bingo.

```sh
level13@SnowCrash:~$ su - level14
Password: # 2A31L79asukciNyi8uppkEuSx
level14@SnowCrash:~$ 
```