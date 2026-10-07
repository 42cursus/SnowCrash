# Objective

As `level09`, the goal is to exploit a vulnerability to gain `flag09`'s privileges and read the flag, which is the password for `level10`.

The flag is gained through the command `getflag`, run as `flag09`.

```sh
level09@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

```sh
level09@SnowCrash:~$ pwd
/home/user/level09

level09@SnowCrash:~$ ll
total 24
dr-x------ 1 level09 level09  140 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level09 level09  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level09 level09 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x 1 flag09  level09 7640 Mar  5  2016 level09*
-r-x------ 1 level09 level09  675 Apr  3  2012 .profile*
----r--r-- 1 flag09  level09   26 Mar  5  2016 token
```


### File type

```sh
level09@SnowCrash:~$ file level09
level09: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x0e1c5a0dfb537112250e1c78d5afec3104abb143, not stripped

level09@SnowCrash:~$ file token 
token: data
```

### Behavior

```sh
level09@SnowCrash:~$ ./level09 
You need to provied only one arg.

level09@SnowCrash:~$ ./level09 token 
tpmhr

level09@SnowCrash:~$ ./level09 00000
01234

level09@SnowCrash:~$ cat token 
f4kmm6p|=�p�n��DB�Du{��
```

```sh
level09@SnowCrash:~$ ltrace ./level09 01234
__libc_start_main(0x80487ce, 2, 0xbffff864, 0x8048aa0, 0x8048b10 <unfinished ...>
ptrace(0, 0, 1, 0, 0xb7e2fe38)                                                                                = -1
puts("You should not reverse this"You should not reverse this
)                                                                           = 28
+++ exited (status 1) +++
```

Pretty clear that we should not analyse the binary, and indeed `ptrace` is used to make debugging fail: the program likely detects a tracer and refuses to run (confirmed by the `-1` return and immediate exit).

Comparing the two behaviors (`00000` → `01234`, i.e. each character shifted by its own position: `0+0=0`, `0+1=1`, `0+2=2`...) shows that the program simply adds the index of each character to its value. We just have to apply the reverse operation to the ciphered `token` file in order to recover the plaintext password.

```py
level09@SnowCrash:~$ cat > python.py
import mmap, sys

str= ""

with open('token', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    i = 0
    for b in mm:
        sys.stdout.write(chr(ord(b) - i))
        i += 1
        if i == 25 :
            break

    mm.close()

sys.stdout.flush()
print ""
```

```sh
level09@SnowCrash:~$ python ./python.py 
f3iji1ju5yuevaus41q1afiuq
```

Bingo.

```sh
level09@SnowCrash:~$ su - flag09
Password: # f3iji1ju5yuevaus41q1afiuq
Don't forget to launch getflag !
flag09@SnowCrash:~$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
flag09@SnowCrash:~$ su - level10
Password: # s5cAJpM8ev6XHw998pRWG728z
level10@SnowCrash:~$ 
```

