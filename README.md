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
## Web
1. **Noobcoder**

   Let's have a look at the challenge description.
   > A junior recently started doing PHP, and makes some random shit. He uses gedit as his go-to editor with a black theme thinking it was sublime.
   So he made this login portal, I am sure he must have left something out. Why don't you give it a try?
   
   First thing that comes to mind after reading this is, there should be some vulnerability/exploit gedit/PHP related. After reading about gedit a little bit, I came to know that it autosaves files with a `~` at end, example: `index.php~`. This can be used to pull source code / files from the server.
   
   On the website link (https://defcon.org.in:6062) provided in the challenge, after trying some guess username and password combination, it is observed that the data is passed to `checker.php` to verify the credentials.
   ![](https://ibin.co/3YI69SDcs3m1.png)
   ![](https://ibin.co/3YI6nPytYmr7.png)
   
   So, I just change the url to https://defcon.org.in:6062/checker.php~ and Voila! I've downloaded the checker.php file and now, have the source code that checks my credentials. Lets have a look at `checker.php~`
   ```
   <html>
   <head></head>
   <body>
   <?php
   if ($_POST["username"] == $_POST["password"] && $_POST["password"] !== $_POST["username"])
       echo "congratulations the flag is d4rk{TODO}c0de";
   else
	    echo "nice try, but try again";
   ?>
   </body>
   </html>
   ```
   Looking at if statement in the file, two things:
   - $x == $y returns true if $x and $y evaluate to same thing irrespective of type
   - $x !== $y returns true if $x and $y are not equal, or they are of not same type
   
   Both above conditions need to be fulfilled so that I can get flag.
   
   I quickly went on with username: "100" and password: 100 but didn't work :D ($\_POST handles everything as string by default). After thinking sometime, I found a workaround. `Username: 100, Password: 1e2`. Now both have different types but get evaluated to same value, thus satisfying both conditions. Click on Sign In, and here we go!
   `congratulations the flag is d4rk{l0l_g3dit_m4ster_roxx}c0de`
2. **Magic**

   Lets have a look at challenge description.
   > Everything disappears magically.
   Can you magically prevent that?
   http://defcon.org.in:6060/index.php
   
   There's hint hidden in description itself. "Everything disappears magically" -> may be something cookie/session related. So, I fire up firebug add-on in firefox and intercept requests and see what happens.
   
   Boom! Have a look at response headers.
   ```
   Connection	close
   Content-type	text/html; charset=UTF-8
   Host	defcon.org.in:6060
   Set-Cookie	
   0=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   1=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   2=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   3=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   4=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   5=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   6=%2B; expires=Thu, 01-Jan-1970 00:00:10 GMT; Max-Age=0; path=/
   ...
   ```
   What's of my interest is the value being set for each id: 0=%2B, 1=%2B, 2=%2B ... so on. These are url_encoded values
   
   I quickly wrote a [python script](http://bit.ly/2w8lthw) to parse these mappings and decode the url_encoded data.
   ```
   $ python hack.py
   ++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>+++++++++++++++++.--.--------------.+++++++++++++.----.-----------
   --.++++++++++++.--------.<------------.<++.>>----.+.<+++++++++++.+++++++++++++.>+++++++++++++++++.-------------
   --.++++.+++++++++++++++.<<.>>-------.<+++++++++++++++.>+++..++++.--------.+++.<+++.<++++++++++++++++++++++++++
   .<++++++++++++++++++++++.>++++++++++++++..>+.----.>------.+++++++.--------.<+++.>++++++++++++..-------.++.
   ```
   Above is nothing but, brainfuck code. Just run it through an online [brainfuck interpreter](https://copy.sh/brainfuck/). This is the output: `username: abERsdhw password: HHealskdwwpr`. Typing these credentials in the index.php form, and submitting it, redirects to `panel.php` with output: `d4rk{c00k13s_4r3_fun}c0de`. Hurray!
## Steg
1. **White**

   We're given a huge png [file](https://hackcon.in/files/fa152fbb6c29afbfaf4f4eb95f898245/final.png) (~47 MB). Usually stegs are most times solved by analysing spectrogram or hex code. Unfortunately, spectrogram didn't provide any hint. So, I opened the png in my hex editor (bless). Interestingly, I found huge base64 code at end of the file. When I decoded it, it gave me another png file with base64 code at the end of the file.
   
   So, I wrote up a [python script](http://bit.ly/2wf5xZd) to recursively decode and store each image until there's no base64 code hidden in the file anymore. Inspecting all the decoded png files, I noticed that the png files contained section of flags. There were total 30 pngs. To assemble them all together and make the flag more easily readable, run the command `montage final-*png -tile 6x5 -geometry +0+0 flag.png`
   
   When you open the flag.png, you can easily read the flag as `d4rk{1mag3_m4n1pul4t10n_f7w}c0d3`
