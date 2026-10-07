# Objective

As `level01`, the goal is to exploit a vulnerability to gain `flag01`'s privileges and read the flag, which is the password for `level02`.

The flag is gained through the command `getflag`, run as `flag01`.

# Content of home

```sh
level01@SnowCrash:~$ pwd
/home/user/level01
level01@SnowCrash:~$ ll
total 12
dr-x------ 1 level01 level01  100 Mar  5  2016 ./
d--x--x--x 1 root    users    340 Aug 30  2015 ../
-r-x------ 1 level01 level01  220 Apr  3  2012 .bash_logout*
-r-x------ 1 level01 level01 3518 Aug 30  2015 .bashrc*
-r-x------ 1 level01 level01  675 Apr  3  2012 .profile*
```

# Further inquiry

## Examination of `/etc/passwd`

The `/etc/passwd` file shows something very interesting!

```sh
level01@SnowCrash:~$ grep -E "level01|flag01" /etc/passwd
level01:x:2001:2001::/home/user/level01:/bin/bash
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

Indeed, the `flag01` user line contains the hash of the password: `42hDRfypTqqnw`. This is a 13-character string, the signature of the traditional DES `crypt(3)` format: a 2-character salt followed by the 11-character hash. Normally, `/etc/passwd` only stores a placeholder (`x`) and the real hash lives in `/etc/shadow`, out of reach of unprivileged users; here it's exposed directly.

This time, let us use `John the Ripper` and try to obtain the real password!

# Resolution

First thing first, let us create a file containing the hash we'll crack.

```sh
sh-5.3$ cat > hash
42hDRfypTqqnw
```

Then open it with `John the Ripper`.

```sh
sh-5.3$ john hash
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 256/256 AVX2])
Will run 24 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
abcdefg          (?)
1g 0:00:00:00 100% 2/3 50.00g/s 6963Kp/s 6963Kc/s 6963KC/s 123456..Sssing
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Bingo! `John` found that the corresponding password is `abcdefg`.

```sh
level01@SnowCrash:~$ su - flag01
Password: # abcdefg
Don't forget to launch getflag !
flag01@SnowCrash:~$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
```