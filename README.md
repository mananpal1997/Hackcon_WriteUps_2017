# Hackcon_WriteUps_2017
WriteUps for CTF event Hackcon 2017 by IIIT-D

# Challenges
## Rev
1. **Keygen**

   You're given a executable file `match_me`
   
   Let's see what it does
   ```
   $ ./match_me
   12 <input_guess>
   Nope <output>
   ```
   Lets have a look at dynamic library calls for no input.
   ```
   $ ltrace ./match_me
   
   __libc_start_main(0x400a03, 1, 0x7ffcd5f460a8, 0x400ad0 <unfinished ...>
   malloc(1000)                                                                                = 0x133c010
   scanf(0x400b6d, 0x133c010, 0x133c010, 0x7f217ad32b20)                                       = 0xffffffff
   malloc(1000)                                                                                = 0x133c810
   strlen("firhfgferfibbqlkdfhh")                                                              = 20
   strlen("firhfgferfibbqlkdfhh")                                                              = 20
   strlen("firhfgferfibbqlkdfhh")                                                              = 20
   strncmp("firhfgferfibbqlkdfhh", "[[[[[[[[[[[[[[[[[[[[", 20)                                 = 11
   puts("Nope"Nope
   )                                                                                = 5
   +++ exited (status 0) +++
   ```
   Interesting. `strcmp` is being called to compare a hardcoded string "firhfgferfibbqlkdfhh" with some other string. Lets run again the ltrace with input "12" (without quotes)
   ```
   $ ltrace ./match_me
   
   __libc_start_main(0x400a03, 1, 0x7ffcd5f460a8, 0x400ad0 <unfinished ...>
   malloc(1000)                                                                                = 0x133c010
   scanf(0x400b6d, 0x133c010, 0x133c010, 0x7f217ad32b20)                                       = 0xffffffff
   malloc(1000)                                                                                = 0x133c810
   strlen("firhfgferfibbqlkdfhh")                                                              = 20
   strlen("firhfgferfibbqlkdfhh")                                                              = 20
   strlen("firhfgferfibbqlkdfhh")                                                              = 20
   strncmp("firhfgferfibbqlkdfhh", "S[[[[[[[[[[[[[[[[[[[", 20)                                 = 11
   puts("Nope"Nope
   )                                                                                = 5
   +++ exited (status 0) +++
   ```
   Nice, so we see that integer 12 is mapped to "S" (See the change of compared string from "[[[[[[..." to "S[[[..."). So, all we have to do is write a simple script to find mappings of all integers from 1-100 to corresponding characters.
   
   So, we get 59:f, 76:i, 65:r and so on.
   
   Key with all mappings done = firhfgferfibbqlkdfhh: 5976657559745958655976555564937857597575
   Let's check our executable with above key
   ```
   $ ./match_me
   5976657559745958655976555564937857597575
   Match
   ```
   Yay! Now we need to send this key to defcon.org.in:8082
   ```
   echo "5976657559745958655976555564937857597575" | nc defcon.org.in 8082
   
   Flag: d4rk{595c7f5b595a59587f595c55557e5f5e57595b5b}c0de
   ```
2. **Keygen-2**
   
   It's the exact same as Keygen-1, but a little different. Let's just connect to the given port and see what does it want?
   ```
   $ nc defcon.org.in 8083
   Send me 10 keys for getting a match separated by \n, followed by a NULL/EOF character.
   ```
   No executable is given for this challenge, and it's given that it's related to Keygen-1. So, we just send the key obtained in previous challenge, repeated 10 times, separated by \n.
   ```
   $ echo "5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575\n5976657559745958655976555564937857597575" | nc defcon.org.in 8083
   
   Flag: d4rk{r0ck1ng_keyg3n_123}c0de
   ```
3. **Not Web**

   We're provided a file named `ihatejs.hs`. No other information is given.
   
   The code was minified and obfuscated, so I unminified it first, and tried to look at it, but couldn't understand much because of the level of obfuscation. So, after a while, I just went on and executed the js file to see if something happens.
   ```
   $ node ihatejs.js
   d4rk{ccjccpbsvrafrcatbpchjydiio}c0de
   ```
   Voila! That was easier than expected!
