# Objective

As `level00`, the goal is to exploit a vulnerability to gain `flag00`'s privileges and read the flag, which is the password for `level01`.

The flag is gained through the command `getflag`, run as `flag00`.

```sh
level00@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

This level doesn't explicitly provide a file to be exploited.

```sh
level00@SnowCrash:~$ pwd
/home/user/level00

level00@SnowCrash:~$ ll
total 12
dr-xr-x---+ 1 level00 level00  100 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-xr-x---+ 1 level00 level00  220 Apr  3  2012 .bash_logout*
-r-xr-x---+ 1 level00 level00 3518 Aug 30  2015 .bashrc*
-r-xr-x---+ 1 level00 level00  675 Apr  3  2012 .profile*
```

# Further inquiry

## Examination of `/etc/passwd`

A quick examination of the `/etc/passwd` file shows nothing special to be exploited.

```sh
level00@SnowCrash:~$ grep -E "level00|flag00" /etc/passwd
level00:x:2000:2000::/home/user/level00:/bin/bash
flag00:x:3000:3000::/home/flag/flag00:/bin/bash
```

## File ownership

Since the flag can only be captured as `flag00`, let us look for whatever file is owned by `flag00`.

```sh
level00@SnowCrash:~$ find / -user flag00 2>/dev/null
/usr/sbin/john
/rofs/usr/sbin/john

level00@SnowCrash:~$ cat /usr/sbin/john /rofs/usr/sbin/john
cdiiddwpgswtgt
cdiiddwpgswtgt
```

Those seemingly gibberish values, alongside with the name of the file (`john`), give a great hint: they could be ciphered. Indeed, `John the Ripper` is a famous password cracking tool, which suggests the value is worth cracking rather than decoding with it directly.

# Resolution

With the use of an online analysis tool such as [Boxentriq](https://www.boxentriq.com/), we are confident enough that we're facing one of the most ancient and simple ciphering techniques, called the [Caesar Cipher](https://en.wikipedia.org/wiki/Caesar_cipher). Since the alphabet only allows 26 possible shifts, it can be brute-forced trivially.

Let us write a small Caesar deciphering tool and try every shift:

```py
import sys

def caesar_letter(origin: str, shift: int) -> str:
    if not origin.isalpha():
        return origin

    index = ord(origin) - ord('a')
    index = (index + shift) % 26

    return chr(ord('a') + index)


def main() -> int:
    if len(sys.argv) != 3:
        return 1

    word = sys.argv[1]

    for i in range(int(sys.argv[2])):
        shifted = "".join(caesar_letter(c, i) for c in word)
        print(f"Shift: {i:2d} -> >{shifted}<")

    return 0

if __name__ == "__main__":
    sys.exit(main())
```

Here's the outcome:

```sh
sh-5.3$ python3 ./level00.py cdiiddwpgswtgt 12
Shift:  0 -> >cdiiddwpgswtgt<
Shift:  1 -> >dejjeexqhtxuhu<
Shift:  2 -> >efkkffyriuyviv<
Shift:  3 -> >fgllggzsjvzwjw<
Shift:  4 -> >ghmmhhatkwaxkx<
Shift:  5 -> >hinniibulxbyly<
Shift:  6 -> >ijoojjcvmyczmz<
Shift:  7 -> >jkppkkdwnzdana<
Shift:  8 -> >klqqllexoaebob<
Shift:  9 -> >lmrrmmfypbfcpc<
Shift: 10 -> >mnssnngzqcgdqd<
Shift: 11 -> >nottoohardhere<   # found it!
```

## Result

```sh
level00@SnowCrash:~$ su - flag00
Password:  # nottoohardhere
Don't forget to launch getflag !
flag00@SnowCrash:~$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias
```
