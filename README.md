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
   $ echo "5976657559745958655976555564937857597575" | nc defcon.org.in 8082
   
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
   
   On the website link (http://defcon.org.in:6062) provided in the challenge, after trying some guess username and password combination, it is observed that the data is passed to `checker.php` to verify the credentials.
   ![](https://ibin.co/3YI69SDcs3m1.png)
   ![](https://ibin.co/3YI6nPytYmr7.png)
   
   So, I just change the url to http://defcon.org.in:6062/checker.php~ and Voila! I've downloaded the checker.php file and now, have the source code that checks my credentials. Lets have a look at `checker.php~`
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
## Crypto
1. **RSA-2**

   > For those, who don't know much about rsa and it's encryption and decryption algorithm, have a look [here](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

   We're given following data
   ```
   n = 109676931776753394141394564514720734236796584022842820507613945978304098920529412415619708851314423671483225500317195833435789174491417871864260375066278885574232653256425434296113773973874542733322600365156233965235292281146938652303374751525426102732530711430473466903656428846184387282528950095967567885381
   e = 49446678600051379228760906286031155509742239832659705731559249988210578539211813543612425990507831160407165259046991194935262200565953842567148786053040450198919753834397378188932524599840027093290217612285214105791999673535556558448523448336314401414644879827127064929878383237432895170442176211946286617205
   c = 103280644092615059984518332609100925251130437801342718478803923990158474621180283788652329522078935869010936203566024336697568861166241737937884153980866061431062015970439320809653170936674539901900312536610219900459284854811622720209705994060764318380465515920139663572083312965314519159261624303103692125635
   ```
   First thing that would come to mind is find p and q by facorizing n. But **LOL**, can't factorise such huge number. Interesting fact is that such lalrge value of e is not usually the case. I googled about it a bit, and found that RSA with such large e is easily prone to [Wiener Attack](https://en.wikipedia.org/wiki/Wiener%27s_attack). So, I quickly wrote a [python script](http://bit.ly/2xnxKx0) to solve this challenge.
   ```
   $ python rsa_2.py
   d4rk{1_70ld_y0u_th15_would_8e_more_difficult}c0de
   ```
## Bacche (Easy Category Challenges)
1. **Rotate-it**

   > Found this weird code can you make something out of it? q4ex{ju0_tvir$_pn3fne_va_PGS???}p0qr
   
   As the name suggests, this is a shift cipher with shift_key = 13. `Flag: d4rk{wh0_give$_ca3sar_in_ctf???}c0de`
2. **High Bass**

   > The secret code just became longer. VGhpcyB3YXMgaW4gYmFzZS02NDogZDRya3t0aGF0XyRpbXBsXzNuMHVnaDRfVX1jMGRl
   
   Again, as the name suggests, "Bass" is hinting towards base64.
   ```
   $ echo "VGhpcyB3YXMgaW4gYmFzZS02NDogZDRya3t0aGF0XyRpbXBsXzNuMHVnaDRfVX1jMGRl" | base64 -d
   This was in base-64: d4rk{that_$impl_3n0ugh4_U}c0de
   ```
3. **File**

   This can't be more easy! You're given an executable. Just run it, and it gives the flag :D
   ```
   $ ./one
   d4rk{s1mpl_linux_execUt4ble}c0de
   ```
4. **Needle**

   We're given a huge text file. Just some regex with grep and we have the flag :D
   ```
   $ cat text.txt | grep "d4rk[{}a-zA-Z0-9_]*"
   ...billows caused by the waxing and d4rk{n33dle_in_a_h4ystck}c0de waning of the moon the parent of Vasudeva's...
   ```
5. **ALL CAPS**

   > OF EKBHMGUKZHJB, Z LWALMOMWMOGF EOHJTK OL Z DTMJGX GY TFEGXOFU AB NJOEJ WFOML GY HSZOFMTVM ZKT KTHSZETX NOMJ EOHJTKMTVM, ZEEGKXOFU MG Z YOVTX LBLMTD; MJT "WFOML" DZB AT LOFUST STMMTKL (MJT DGLM EGDDGF), HZOKL GY STMMTKL, MKOHSTML GY STMMTKL, DOVMWKTL GY MJT ZAGRT, ZFX LG YGKMJ. MJT KTETORTK XTEOHJTKL MJT MTVM AB HTKYGKDOFU MJT OFRTKLT LWALMOMWMOGF. MJZFQL YGK KTZXOFU MJZM, JTKT'L BGWK YSZU: X4KQ{MKB_YZEEJ3_OYMJOL_MGG_LODHTS}E0XT
   
   Look closesly at the end, it looks like substitution cipher. Easy!
   > IN CRYPTOGRAPHY, A SUBSTITUTION CIPHER IS A METHOD OF ENCODING BY WHICH UNITS OF PLAINTEXT ARE REPLACED WITH CIPHERTEXT, ACCORDING TO A FIXED SYSTEM; THE "UNITS" MAY BE SINGLE LETTERS (THE MOST COMMON), PAIRS OF LETTERS, TRIPLETS OF LETTERS, MIXTURES OF THE ABOVE, AND SO FORTH. THE RECEIVER DECIPHERS THE TEXT BY PERFORMING THE INVERSE SUBSTITUTION. THANKS FOR READING THAT, HERE'S YOUR FLAG: D4RK{TRY_FACCH3_IFTHIS_TOO_SIMPEL}C0DE

6. **Caves**

   We're given an image and we need to decipher it.
   
   ![](https://hackcon.in/files/f97abae6df054a8b8487e34c779ec3b1/cave.png)
   
   A little bit of googling, and we find out it's [Egyptian Glyph Alphabet](http://www.virtual-egypt.com/newhtml/hieroglyphics/sample/alphabet.gif)
   After decoding, we get `THE FLAG IS EGYPTISBETTERTHANYOU`
7. **RSA-1**

   Very simple RSA. All the needed things are given.
   ```
   p = 152571978722786084351886931023496370376798999987339944199021200531651275691099103449347349897964635706112525455731825020638894818859922778593149300143162720366876072994268633705232631614015865065113917174134807989294330527442191261958994565247945255072784239755770729665527959042883079517088277506164871850439
   q = 147521976719041268733467288485176351894757998182920217874425681969830447338980333917821370916051260709883910633752027981630326988193070984505456700948150616796672915601007075205372397177359025857236701866904448906965019938049507857761886750656621746762474747080300831166523844026738913325930146507823506104359
   c = 8511718779884002348933302329129034304748857434273552143349006561412761982574325566387289878631104742338583716487885551483795770878333568637517519439482152832740954108568568151340772337201643636336669393323584931481091714361927928549187423697803637825181374486997812604036706926194198296656150267412049091252088273904913718189248082391969963422192111264078757219427099935562601838047817410081362261577538573299114227343694888309834727224639741066786960337752762092049561527128427933146887521537659100047835461395832978920369260824158334744269055059394177455075510916989043073375102773439498560915413630238758363023648
   e = 65537
   ```
   Simple [python script](http://bit.ly/2wStLuE) to solve it.
   ```
   $ python rsa_1.py
   d4rk{s1mpl3_rsa_n0t_th1s_34sy_next_time}c0de
   ```
8. **flag.txt**

   Let's look at description.
   > Even google won't be able to find the flag. Still you can try if you want: http://defcon.org.in:6061/
   
   First thing that strikes from "google won't be able to find the flag" => there's got to be robots.txt file :D
   
   Hitting http://defcon.org.in:6061/robots.txt returns
   ```
   User-agent: *
   Disallow: /500786fbfb9cadc4834cd3783894239d
   ```
   Now, I got stuck at this for a while as I was trying to access http://defcon.org.in:6061/500786fbfb9cadc4834cd3783894239d but DUH, that's a directory, not a file. That's why it kept giving me 404. Hmmm, must be a file in that directory then, that I need to access.
   
   A couple more minutes, and it struck me. What's the name of challenge LOL? (flag.txt) :P
   
   So, I quickly hit the page http://defcon.org.in:6061/500786fbfb9cadc4834cd3783894239d/flag.txt in my browser and Voila! `The flag is d4rk{r0b075_7x7_4r3_v3ry_c0mm0n}c0de`
9. **Numbers**

   > These are some numbers, try to make sense of them.
   
   We're given a huge text file with data like `(361, 15, 0, 0, 0) (267, 77, 1020, 1020, 1020) (380, 272, 1020, 1020, 1020) (171, 340, 0, 0, 0)...`. After analysing for sometime, I realised that these numbers maybe (x, y, r, g, b) denoting x and y coordinates of a pixel and it's r-g-b value. And it's a binary image as rgb values of pixels were same and either 0 or 1020.
   
   So, I wrote a [python script](http://bit.ly/2wia6SQ) to parse this text file and make an image out of these numbers. Maybe the image will be having flag.
   
   Surprisingly, it was not yet the flag. It was a qr-code.
   
   ![](https://ibin.co/3YRdzByM3aS1.jpg)
   
   Still not over! When I decoded the qr-code, I got `ZDRya3txcmMwZDM1XzRyM19mdW5fdzE3aF9wMWx9YzBkZQpSYW5kb20gVGV4dCBJZ25vcmUgVGhpcyAuLi4uLi4uLi4uLi4uPT09PT09PT09PT09PT09PT09PT09`
   
   After thinking for a bit, I thought to go wtih the thought that it might be base64 string (length is multiple of 4). And, I was right!
   ```
   $ echo "ZDRya3txcmMwZDM1XzRyM19mdW5fdzE3aF9wMWx9YzBkZQpSYW5kb20gVGV4dCBJZ25vcmUgVGhpcyAuLi4uLi4uLi4uLi4uPT09PT09PT09PT09PT09PT09PT09" | base64 -d
   d4rk{qrc0d35_4r3_fun_w17h_p1l}c0de
   Random Text Ignore This .............=====================
   ```
