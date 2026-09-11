# CorporateSecrets Lab

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/corporatesecrets/](https://cyberdefenders.org/blueteam-ctf-challenges/corporatesecrets/)

Suggested tools: FTK Imager, Registry Explorer, RegRipper, HxD, DB Browser for SQLite, HindSight, Event Log Explorer, MFTDump

Tactics: Execution, Stealth, Credential Access, Discovery, Collection

# Scenario

A Windows forensics challenge prepared by Champlain College Digital Forensics Association for their yearly CTF.

Windows Image Forensics Case created by AccessData® FTK® Imager 4.2.1.4

Acquired using: ADI4.2.1.4

**Information for F:\DFA_Windows\DFA_SP2020_Windows:**

Physical Evidentiary Item (Source) Information:

- [Device Info]
    - Source Type: Physical
- [Drive Geometry]
    - Cylinders: 6,527
    - Heads: 255
    - Sectors per Track: 63
    - Bytes per Sector: 512
    - Sector Count: 104,857,600

[Physical Drive Information]

- Drive Interface Type: lsilogic [Image]
- Image Type: VMWare Virtual Disk
- Source data size: 51200 MB
- Sector count: 104857600

Image Information:

- Segment list:
    - F:\DFA_Windows\DFA_SP2020_Windows.E01
    - F:\DFA_Windows\DFA_SP2020_Windows.E02
    - F:\DFA_Windows\DFA_SP2020_Windows.E03
    - F:\DFA_Windows\DFA_SP2020_Windows.E04
    - F:\DFA_Windows\DFA_SP2020_Windows.E05
    - F:\DFA_Windows\DFA_SP2020_Windows.E06
    - F:\DFA_Windows\DFA_SP2020_Windows.E07
    - F:\DFA_Windows\DFA_SP2020_Windows.E08
    - F:\DFA_Windows\DFA_SP2020_Windows.E09

Your objective as a SOC analyst is to analyze the image and answer the question.

# Questions

Q1- What is the current build number on the system?

Answer: `16299`

Reason: Analysis of the `SOFTWARE` registry hive extracted from the `DFA_SP2020_Windows` image identified the operating system build under the `Microsoft\Windows NT\CurrentVersion` key. Both the `CurrentBuild` and `CurrentBuildNumber` values are set to `16299`, corresponding to Windows 10 version 1709 (Fall Creators Update), establishing the OS baseline for the remainder of the investigation.

```bash
$ reglookup -p "/Microsoft/Windows NT/CurrentVersion" Windows/System32/config/SOFTWARE | grep CurrentBuild            
/Microsoft/Windows NT/CurrentVersion/CurrentBuild,SZ,16299,
/Microsoft/Windows NT/CurrentVersion/CurrentBuildNumber,SZ,16299,
```

Q2- How many users are there?

Answer: 6

Reason: Enumeration of user profiles on the system was performed against the `ProfileList` key within the SOFTWARE registry hive, which maintains one subkey per local or domain profile keyed by SID. Six distinct `S-1-5-21-` prefixed SID subkeys were identified under `Microsoft\Windows NT\CurrentVersion\ProfileList`, indicating six user profiles existed on the host.

```bash
$ reglookup -p "/Microsoft/Windows NT/CurrentVersion/ProfileList" Windows/System32/config/SOFTWARE | grep -cE '/ProfileList/S-1-5-21-[0-9-]+,' 
6
```

Q3- What is the CRC64 hash of the file `fruit_apricot.jpg`?

Answer: `ED865AA6DFD756BF`

Reason: Hash verification of a picture file recovered from a user profile was performed to establish a unique identifier for later correlation. The file `fruit_apricot.jpg`, located at `Users/hansel.apricot/Pictures/Saved Pictures/fruit_apricot.jpg` and 112596 bytes in size, produced a CRC64 hash of `ED865AA6DFD756BF` when processed with `7z h -scrcCRC64`.

```bash
$ 7z h -scrcCRC64 ./Users/hansel.apricot/Pictures/Saved\ Pictures/fruit_apricot.jpg 

Scanning
1 file, 112596 bytes (110 KiB)                           

CRC64                     Size  Name
---------------- -------------  ------------
ED865AA6DFD756BF        112596  fruit_apricot.jpg
---------------- -------------  ------------
```

Q4- What is the logical size of the file "strawberry.jpg" in bytes?

Answer: 72448

Reason: File size verification was performed on a picture recovered from another user profile for later correlation purposes. The file `strawberry.jpg`, located at `Users/suzy.strawberry/Pictures/strawberry.jpg`, has a logical size of `72448` bytes as reported by `stat`.

```bash
$ stat ./Users/suzy.strawberry/Pictures/strawberry.jpg
  File: ./Users/suzy.strawberry/Pictures/strawberry.jpg
  Size: 72448           Blocks: 142        IO Block: 4096   regular file
[...]
```

Q5- What is the processor architecture of the system? (one word)

Answer: AMD64

Reason: The processor architecture of the system was determined by examining the `Session Manager\Environment` key within the SYSTEM registry hive, which stores environment variables set at boot including processor identification data. The `PROCESSOR_ARCHITECTURE` value is set to `AMD64`, indicating a 64-bit x86-compatible architecture, while `PROCESSOR_IDENTIFIER` further identifies the physical CPU as an `Intel64 Family 6 Model 44 Stepping 2 GenuineIntel` processor.

```bash
$ reglookup -p "/ControlSet001/Control/Session Manager/Environment" Windows/System32/config/SYSTEM \
  | grep -E 'PROCESSOR_ARCHITECTURE|PROCESSOR_IDENTIFIER|PROCESSOR_ARCHITECTUREW6432'
/ControlSet001/Control/Session Manager/Environment/PROCESSOR_ARCHITECTURE,SZ,AMD64,
/ControlSet001/Control/Session Manager/Environment/PROCESSOR_IDENTIFIER,SZ,Intel64 Family 6 Model 44 Stepping 2%2C GenuineIntel,
```

Q6- Which user has a photo of a dog in their recycling bin?

Answer: `hansel.apricot`

Reason: Recovery of deleted files was performed against the `$Recycle.Bin` structure, which retains recycled content under per-user subfolders named by SID. A JPEG image recovered at `$Recycle.Bin/S-1-5-21-2446097003-76624807-2828106174-1005/$RGETALS.jpg` was visually confirmed to depict a dog. The trailing RID `1005` (hexadecimal `0x3ED`) was resolved to a username via the SAM registry hive's `Users\Names` key, identifying the owning account as `hansel.apricot`.

```bash
$ open \$Recycle.Bin/S-1-5-21-2446097003-76624807-2828106174-1005/\$RGETALS.jpg # dog photo, confirmed

$ reglookup -p "/SAM/Domains/Account/Users/Names" Windows/System32/config/SAM | grep "000003ED"
/SAM/Domains/Account/Users/Names/hansel.apricot/,0x000003ED,(null),
```

![**Doggo!**](image.png)

**Doggo!**

Q7- What type of file is `vegetable`? Provide the extension without a dot.

Answer: `7z`

Reason: File type identification was performed on a suspiciously extensionless file discovered in a user's Pictures folder, since file extensions can be renamed or stripped to disguise content. The `file` utility examined the magic bytes of `Users/miriam.grapes/Pictures/vegetable` and identified it as `7-zip archive data, version 0.4`, indicating the true file type is a `7z` archive rather than an image, despite its location among picture files.

```bash
$ file ./Users/miriam.grapes/Pictures/vegetable
./Users/miriam.grapes/Pictures/vegetable: 7-zip archive data, version 0.4
```

Q8- What type of girls does Miriam Grapes design phones for (Target audience)?

Answer: VSCO

Reason: Browser history analysis was performed against Firefox's `places.sqlite` database, which stores visited URLs, page titles, and visit metadata. A search query in the `moz_places` table for `what kind of phones do vsco girls enjoy` was identified, submitted via Google search on `2020-04-11` (Unix microsecond timestamp `1586635209570000`), indicating the user researched phone preferences targeted at `VSCO` girls as part of product or marketing design research.

```bash
# Firefox places.sqlite
8	https://www.google.com/search?client=firefox-b-1-d&q=what+kind+of+phones+do+vsco+girls+enjoy	what kind of phones do vsco girls enjoy - Google Search	moc.elgoog.www.	1	0	1	2000	1586635209570000	t9oizj3KSU3M	0	47357818170812			3
```

Q9- What is the name of the device?

Answer: `DESKTOP-3A4NLVQ`

Reason: The device hostname was retrieved from the `ComputerName\ComputerName` key within the SYSTEM registry hive's `ControlSet001\Control` branch, which stores the NetBIOS/computer name assigned to the system. The `ComputerName` value is set to `DESKTOP-3A4NLVQ`, last modified `2020-04-03 02:04:14`.

```bash
$ reglookup -p "/ControlSet001/Control/ComputerName/ComputerName" Windows/System32/config/SYSTEM
PATH,TYPE,VALUE,MTIME
/ControlSet001/Control/ComputerName/ComputerName,KEY,,2020-04-03 02:04:14
/ControlSet001/Control/ComputerName/ComputerName/,SZ,mnmsrvc,
/ControlSet001/Control/ComputerName/ComputerName/ComputerName,SZ,DESKTOP-3A4NLVQ,
```

Q10- What is the SID of the machine?

Answer: `S-1-5-21-2446097003-76624807-2828106174`

Reason: The machine's domain/local SID prefix was extracted from the `ProfileList` key within the SOFTWARE registry hive, since all local account SIDs on a given machine share a common machine-identifier prefix before their unique RID suffix. Filtering the profile subkey names for the `S-1-5-21-` pattern and deduplicating confirmed a single consistent machine SID of `S-1-5-21-2446097003-76624807-2828106174` across all local accounts.

```bash
$ reglookup -p "/Microsoft/Windows NT/CurrentVersion/ProfileList" Windows/System32/config/SOFTWARE \
  | grep -oE 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+' | uniq
S-1-5-21-2446097003-76624807-2828106174
```

Q11- How many web browsers are present?

Answer: 5

Reason: Browser presence on the system was enumerated by searching all user profiles for filenames and directory paths associated with common browser names, then verifying genuine installations versus stray shortcuts. Five distinct browsers were identified: `Internet Explorer`, present as a built-in component across all profiles; `Google Chrome`, evidenced by populated application data under `Users/jim.tomato/AppData/Local/Google/Chrome` and `Users/tim.apple/AppData/Local/Google/Chrome`; `Mozilla Firefox`, evidenced by populated profile directories `Users/miriam.grapes/AppData/Roaming/Mozilla/Firefox/Profiles/9far2v52.default-release` and `Users/tim.apple/AppData/Roaming/Mozilla/Firefox/Profiles/d6kc02w6.default-release`; `Microsoft Edge`, evidenced by an installed application directory at `Users/tim.apple/AppData/Local/Microsoft/Edge` alongside its Beta, Dev, and SXS channel folders and `EdgeUpdate`; and `Tor Browser`, evidenced by a portable installation at `Program1/Browser` containing `TorBrowser`, `tbb_version.json`, and a Firefox-derived `firefox.exe`, corroborated by `Start Tor Browser.lnk` shortcuts on `jim.tomato`'s desktop and Start Menu.

```bash
$ find Users \( -iname '*chrome*' -o -iname '*firefox*' -o -iname '*edge*' -o -iname '*iexplore*' -o -iname '*tor*browser*' \) 2>/dev/null
Users/jim.tomato/AppData/Local/Google/Chrome
Users/miriam.grapes/AppData/Roaming/Mozilla/Firefox/Profiles/9far2v52.default-release
Users/tim.apple/AppData/Local/Microsoft/Edge
Users/tim.apple/AppData/Roaming/Mozilla/Firefox/Profiles/d6kc02w6.default-release
Users/jim.tomato/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Start Tor Browser.lnk

$ ls Program1/Browser
TorBrowser  tbb_version.json  firefox.exe  omni.ja  ...
```

Q12- How many super secret CEO plans does Tim have? (Dr. Doofenshmirtz Type Beat)

Answer: 4

Reason: Content extraction was performed on an OpenDocument text file discovered in the CEO's document folder, since ODT files are ZIP-based containers whose plaintext is not visible without proper parsing. The file `Users/tim.apple/Documents/secret.odt` was parsed with `odt2txt`, revealing a list titled "Super secret CEO plans" containing four entries: `Take over the world`, `Destroy Google`, `Release the new Fruit Phone`, and `Fire Jim Tomato`.

```bash
$ odt2txt Users/tim.apple/Documents/secret.odt 

Super secret CEO plans:

Take over the world

Destroy Google

Release the new Fruit Phone

Fire Jim Tomato
```

Q13- Which employee does Tim plan to fire? (He's Dead, Tim. Enter the full name - two words - space separated)

Answer: Jim Tomato

Reason: Analysis of the CEO's secret plans document, previously extracted via `odt2txt` from `Users/tim.apple/Documents/secret.odt`, identified the fourth listed plan as `Fire Jim Tomato`, indicating the employee targeted for termination is `Jim Tomato`.

Q14- What was the last used username? (I didn't start this conversation, but I'm ending it!)

Answer: `jim.tomato`

Reason: Determination of the last used login username was performed against the `Winlogon` key within the SOFTWARE registry hive, which tracks the most recently authenticated interactive user for auto-logon and UI display purposes. The `LastUsedUsername` value is set to `jim.tomato`, distinct from the `DefaultUserName` value of `miriam.grapes`, indicating `jim.tomato` was the most recent account to log on interactively to the system.

```bash
$ reglookup -p "/Microsoft/Windows NT/CurrentVersion/Winlogon" Windows/System32/config/SOFTWARE \
  | grep -iE 'DefaultUserName|LastUsedUsername|AltDefaultUserName|DefaultDomainName|AutoLogonSID|LastLogon'
/Microsoft/Windows NT/CurrentVersion/Winlogon/AutoLogonSID,SZ,S-1-5-21-2446097003-76624807-2828106174-1003,
/Microsoft/Windows NT/CurrentVersion/Winlogon/LastUsedUsername,SZ,jim.tomato,
/Microsoft/Windows NT/CurrentVersion/Winlogon/DefaultUserName,SZ,miriam.grapes,
/Microsoft/Windows NT/CurrentVersion/Winlogon/DefaultDomainName,SZ,DESKTOP-3A4NLVQ,
```

Q15- What was the role of the employee Tim was flirting with?

Answer: secretary

Reason: Browser history analysis of Tim Apple's Firefox `places.sqlite` database identified a search query submitted on `2020-04-09` (Unix microsecond timestamp `1586465107246000`) for `is it ok to flirt with my secretary`, indicating the employee Tim was flirting with held the role of `secretary`.

```bash
# Time's Firefox places
10	https://www.google.com/search?source=hp&ei=EomPXvvrMvqlytMP_sGVeA&q=is+it+ok+to+flirt+with+my+secretary&oq=is+it+ok+to+flirt+with+my+secretary[....]	is it ok to flirt with my secretary - Google Search	moc.elgoog.www.	1	0	0	100	1586465107246000	1aOiX1lfBBVy	0	47357820280294			4
```

Q16- What is the SID of the user `suzy.strawberry`?

Answer: `1004`

Reason: Resolution of `suzy.strawberry`'s SID was performed against the `ProfileList` key within the SOFTWARE registry hive, which maps each local SID subkey to its associated profile path via `ProfileImagePath`. The subkey `S-1-5-21-2446097003-76624807-2828106174-1004` maps to `C:\Users\suzy.strawberry`, identifying her relative identifier (RID) as `1004`.

```bash
$ reglookup -p "/Microsoft/Windows NT/CurrentVersion/ProfileList" Windows/System32/config/SOFTWARE | grep suzy
/Microsoft/Windows NT/CurrentVersion/ProfileList/S-1-5-21-2446097003-76624807-2828106174-1004/ProfileImagePath,EXPAND_SZ,C:\Users\suzy.strawberry,
```

Q17- List the file path for the install location of the Tor Browser.

Answer: `C:\Program1`

Reason: The install location of the Tor Browser was determined by searching the file system for directories named `Tor`, which identified `Program1/Browser/TorBrowser/Tor` and `Program1/Browser/TorBrowser/Data/Tor` as the browser's internal Tor client directories. Tracing this path upward to the top-level installation root places the Tor Browser install location at `C:\Program1`, a nonstandard directory name deviating from the default `C:\Program Files` convention, suggesting an attempt to obscure the installation from casual inspection.

```bash
$ find . -iname "Tor"
./Program1/Browser/TorBrowser/Tor
./Program1/Browser/TorBrowser/Data/Tor
```

Q18- What was the URL for the YouTube video watched by Jim?

Answer: `hxxps://www.youtube.com/watch?v=Y-CsIqTFEyY`

Reason: Browser history analysis of Jim Tomato's Chrome `History` SQLite database identified a visited URL of `hxxps://www.youtube.com/watch?v=Y-CsIqTFEyY`, titled "How To Hack Into a Computer," indicating Jim researched hacking techniques via YouTube, consistent with a potential precursor to malicious activity against the corporate environment.

```bash
# Chrome History
12	https://www.youtube.com/watch?v=Y-CsIqTFEyY	How To Hack Into a Computer - YouTube	1	0	13231139973903820	0
```

Q19- Which user installed LibreCAD on the system?

Answer: `miriam.grapes`

Reason: File system enumeration for the LibreCAD installer identified two copies of `LibreCAD-Installer-2.1.3.exe` located in `Users/miriam.grapes/Downloads`, corroborated by an associated Prefetch execution artifact `LIBRECAD-INSTALLER-2.1.3.EXE-D994778F.pf` in `Windows/Prefetch`, confirming the installer was both downloaded and executed under the `miriam.grapes` user profile.

```bash
$ find . -iname "*LibreCAD-Installer*"
./Windows/Prefetch/LIBRECAD-INSTALLER-2.1.3.EXE-D994778F.pf
./Windows/Prefetch/LIBRECAD-INSTALLER-2.1.3.EXE-D994778F.pf.FileSlack
./Users/miriam.grapes/Downloads/LibreCAD-Installer-2.1.3 (1).exe
./Users/miriam.grapes/Downloads/LibreCAD-Installer-2.1.3.exe
```

Q20- How many times `admin` logged into the system?

Answer: 10

Reason: Login frequency for the `admin` account was determined via RegRipper's `samparse` plugin against the SAM registry hive, which enumerates per-account metadata including login counts stored in the account's F-value structure. The account with RID `1001`, corresponding to `admin`, shows a `Login Count` of `10`.

```bash
$ regripper -r ./Windows/System32/config/SAM -p samparse | grep 1001 -A 10 | grep Count
Launching samparse v.20220921
Login Count     : 10
```

Q21- What is the name of the DHCP domain the device was connected to?

Answer: `fruitinc.xyz`

Reason: The DHCP-assigned domain was determined by examining the `Tcpip\Parameters` key within the SYSTEM registry hive, which stores network configuration data supplied by DHCP. Both the global `DhcpDomain` value and the per-interface value under `{f2329ece-8884-4fbd-ad6e-3925da11ddd7}` are set to `fruitinc.xyz`, identifying the corporate domain the device was connected to.

```bash
$ reglookup -p "/ControlSet001/Services/Tcpip/Parameters" ./Windows/System32/config/SYSTEM | grep -i dhcpdomain
/ControlSet001/Services/Tcpip/Parameters/DhcpDomain,SZ,fruitinc.xyz,
/ControlSet001/Services/Tcpip/Parameters/Interfaces/{f2329ece-8884-4fbd-ad6e-3925da11ddd7}/DhcpDomain,SZ,fruitinc.xyz,
```

Q22- What time did Tim download his background image? (Oh Boy 3AM . Answer in MM/DD/YYYY HH:MM format (UTC).)

Answer: `04/05/2020 03:49`

Reason: File modification timestamp analysis was performed using `exiftool` against `hqdefault.jpg`, located at `Part2/root/Users/tim.apple/Pictures/Saved Pictures`, which Tim used as his desktop background image. The `File Modification Date/Time` field reports `2020-04-05 03:49:54+00:00`, indicating the file was downloaded to disk at `04/05/2020 03:49` UTC.

![image.png](image%201.png)

Q23- How many times did Jim launch the Tor Browser?

Answer: 2

Reason: Application launch frequency for Jim Tomato's Tor Browser was determined via RegRipper's `recentapps` plugin against his `NTUSER.DAT` hive, which tracks per-user application usage under the RecentApps registry structure. The entry for `C:\Program1\Browser\firefox.exe` (Tor Browser's underlying executable) shows a `LaunchCount` of `2`, with a `LastAccessedTime` of `2020-04-16 04:52:28Z`.

```bash
$ regripper -r ./Users/jim.tomato/NTUSER.DAT -p recentapps | grep Program1 -A 3 
Launching recentapps v.20200515
AppId           : C:\Program1\Browser\firefox.exe
LastAccessedTime: 2020-04-16 04:52:28Z
LaunchCount     : 2
```

Q24- There is a PNG photo of an iPhone in Grapes's files. Find it and provide the SHA-1 hash.

Answer: `537fe19a560ba3578d2f9095dc2f591489ff2cde`

Reason: Steganographic analysis of a JPEG image depicting a flip phone, found within Miriam Grapes's files, was performed using `binwalk` to identify embedded file signatures. A PNG file header was located at offset `0x174A` (decimal `5962`) within `samplePhone.jpg`, indicating a second image was appended to or embedded within the carrier JPEG. Carving out this embedded PNG and computing its SHA-1 hash produced `537fe19a560ba3578d2f9095dc2f591489ff2cde`, confirmed to depict an iPhone.

```bash
$ binwalk  --dd=".*" samplePhone.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
5962          0x174A          PNG image, 1000 x 1000, 8-bit/color RGBA, non-interlaced
6003          0x1773          Zlib compressed data, best compression

$ sha1sum 174A
537fe19a560ba3578d2f9095dc2f591489ff2cde  174A
```

Q25- When was the last time a docx file was opened on the device? (An apple a day keeps the docx away. Answer in UTC, YYYY-MM-DD HH:MM:SS)

Answer: `2020-04-11 23:23:36`

Reason: The last opened `.docx` file on the system was determined via RegRipper's `recentdocs` plugin against `jim.tomato`'s `NTUSER.DAT` hive, which tracks recently accessed documents by file extension under the `RecentDocs` registry key. The `.docx` subkey's `LastWrite Time`, reflecting the most recent update to that extension's MRU (Most Recently Used) list, is `2020-04-11 23:23:36Z`, with `CompanySecrets.docx` present among the tracked entries.

```bash
$ regripper -r ./Users/jim.tomato/NTUSER.DAT -p recentdocs | grep docx -A 5
Launching recentdocs v.20200427
  3 = Document1.docx
  1 = Untitled 1.docx
  2 = CompanySecrets.docx
  0 = Downloads

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx
LastWrite Time 2020-04-11 23:23:36Z
MRUListEx = 2,0,1
  2 = Document1.docx
  0 = Untitled 1.docx
  1 = CompanySecrets.docx

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder
LastWrite Time 2020-04-16 04:48:53Z
MRUListEx = 1,0
  1 = The Internet
```

Q26- How many entries does the MFT of the filesystem have?

Answer: 219904

Reason: The total number of MFT entries was determined by dividing the size of the `$MFT` file by the fixed NTFS MFT record size of 1024 bytes, rather than relying on raw output line counts from a parsing tool, since `analyzeMFT`'s CSV output included additional attribute rows beyond one-row-per-record. The `$MFT` file size of `225181696` bytes, established during initial system profiling, divides evenly by `1024` to yield `219904`, confirming the filesystem's MFT contains `219904` entries with no remainder.

```bash
$ stat -c%s '$MFT'
225181696

$ python3 -c "print(225181696 / 1024)"
219904.0
```

Q27- Tim wanted to fire an employee because they were ......? (Be careful what you wish for)

Answer: stinky

Reason: Browser history analysis of Tim Apple's Chrome `History` database identified a Google search query with intentional letter-doubling obfuscation: `hhoww ddoo i niicceelyy fiirre mmy sttiinkyy eemmpplooyye`, which decodes to "how do i nicely fire my stinky employee." This indicates Tim sought to terminate an employee on the grounds that they were `stinky`.

```bash
# Chrome History
3	https://www.google.com/search?q=hhoww+ddoo+i+niicceelyy+fiirre+mmy+sttiinkyy+eemmpplooyye&nfpr=1&sa=X&ved=2ahUKEwi1y4mNmdzoAhWukHIEHSCfDzMQvgUoAXoECAwQJw&biw=988&bih=620	hhoww ddoo i niicceelyy fiirre mmy sttiinkyy eemmpplooyye - Google Search	2	0	13230938189881044	0
```

Q28- What cloud service was a Startup item for the user admin?

Answer: `OneDrive`

Reason: Startup persistence entries for the `admin` user were enumerated via RegRipper's `run` plugin against `admin`'s `NTUSER.DAT` hive, which reports auto start programs registered under `Software\Microsoft\Windows\CurrentVersion\Run`. The single entry found is `OneDrive`, launching `C:\Users\admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background`, last written `2020-04-03 02:14:39Z`, identifying `OneDrive` as the cloud service configured to start automatically for this user.

```bash
$ regripper -r ./Users/admin/NTUSER.DAT -p run | grep -v "not found"
Launching run v.20200511
run v.20200511
(Software, NTUSER.DAT) [Autostart] Get autostart key contents from Software hive

Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2020-04-03 02:14:39Z
  OneDrive - "C:\Users\admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background

Software\Microsoft\Windows\CurrentVersion\Run has no subkeys.
```

Q29- Which Firefox prefetch file has the most runtimes? (Flag format is )

Answer: `FIREFOX.EXE-A606B53C.pf`/21

Reason: Execution frequency for each distinct Firefox installation on the system was determined using `sccainfo` against all three `FIREFOX.EXE-*.pf` Prefetch files found under `Windows/Prefetch`, since each hash suffix represents a different executable path referenced by the OS. `FIREFOX.EXE-A606B53C.pf` recorded a `Run count` of `21`, the highest of the three, compared to `10` for `FIREFOX.EXE-20153F0F.pf` and `4` for `FIREFOX.EXE-B4420372.pf`.

```bash
$ find Windows/Prefetch -iname "FIREFOX*" | grep -vE "Slack|INSTALLER"
Windows/Prefetch/FIREFOX.EXE-A606B53C.pf
Windows/Prefetch/FIREFOX.EXE-B4420372.pf
Windows/Prefetch/FIREFOX.EXE-20153F0F.pf

# for f in Windows/Prefetch/FIREFOX.EXE-A606B53C.pf Windows/Prefetch/FIREFOX.EXE-B4420372.pf Windows/Prefetch/FIREFOX.EXE-20153F0F.pf; do 
  echo "=== $f ==="
  sccainfo "$f" | grep -iE "run count|executable|prefetch hash"
done
=== Windows/Prefetch/FIREFOX.EXE-A606B53C.pf ===
        Prefetch hash                   : 0xa606b53c
        Executable filename             : FIREFOX.EXE
        Run count                       : 21
=== Windows/Prefetch/FIREFOX.EXE-B4420372.pf ===
        Prefetch hash                   : 0xb4420372
        Executable filename             : FIREFOX.EXE
        Run count                       : 4
=== Windows/Prefetch/FIREFOX.EXE-20153F0F.pf ===
        Prefetch hash                   : 0x20153f0f
        Executable filename             : FIREFOX.EXE
        Run count                       : 10
```

Q30- What was the last IP address the machine was connected to?

Answer: `192.168.2.242`

Reason: The last DHCP-assigned IP address was determined by examining the `Tcpip\Parameters\Interfaces` key within the `SYSTEM` registry hive. The interface `{f2329ece-8884-4fbd-ad6e-3925da11ddd7}`, previously identified as the machine's network adapter tied to the `fruitinc.xyz` domain, holds a `DhcpIPAddress` value of `192.168.2.242`, identifying the last IP address leased to the machine.

```bash
$ reglookup -p "/ControlSet001/Services/Tcpip/Parameters/Interfaces" Windows/System32/config/SYSTEM | grep -i "DhcpIPAddress"
/ControlSet001/Services/Tcpip/Parameters/Interfaces/{f2329ece-8884-4fbd-ad6e-3925da11ddd7}/DhcpIPAddress,SZ,192.168.2.242,
```

Q31- Which user had the most items pinned to their taskbar?

Answer: `admin`

Reason: Taskbar pin counts were enumerated across all user profiles by counting `.lnk` shortcut files within each user's `AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar` directory, the standard location Windows uses to store taskbar-pinned shortcuts. The `admin` profile had `2` pinned items, more than any other user, each of whom had only `1`.

```bash
$ for d in Users/*/AppData/Roaming/Microsoft/Internet\ Explorer/Quick\ Launch/User\ Pinned/TaskBar; do 
  echo -n "$d  "
  ls -1 "$d"/*.lnk 2>/dev/null | wc -l
done
Users/admin/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar  2
Users/hansel.apricot/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar  1
Users/jim.tomato/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar  1
Users/miriam.grapes/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar  1
Users/suzy.strawberry/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar  1
```

Q32- What was the last run date of the executable with an MFT record number of 164885? (Format: `MM/DD/YYYY HH:MM:SS (UTC)`.)

Answer: `04/12/2020 02:32:09`

Reason: The executable at MFT record `164885` was identified via `analyzeMFT`'s CSV output as `7zG.exe`, the GUI component of 7-Zip. Its last run date was determined using `sccainfo` against the corresponding Prefetch file `7ZG.EXE-0F8C4081.pf`, whose most recent `Last run time` entry is `Apr 12, 2020 02:32:09.454920800 UTC`, formatted as `04/12/2020 02:32:09`.

```bash
$ analyzemft -f '$MFT' -o /tmp/mft.csv --csv

$ grep -a "^164885," /tmp/mft.csv
164885,Valid,In Use,File,1,142400,0,7zG.exe[...]

$ sccainfo Windows/Prefetch/7ZG.EXE-0F8C4081.pf | grep -i last
        Last run time: 1                : Apr 12, 2020 02:32:09.454920800 UTC
        Last run time: 2                : Apr 12, 2020 01:29:05.794204900 UTC
        Last run time: 3                : Apr 11, 2020 23:23:06.523711900 UTC
        Last run time: 4                : Apr 11, 2020 23:20:36.773378900 UTC
        Last run time: 5                : Apr 11, 2020 23:17:34.806741900 UTC
[...]
```

Q33- What is the log file sequence number for the file `fruit_Assortment.jpg`?

Answer: `1276820064`

Reason: The record for `fruit_Assortment.jpg` was located at MFT record number `180174` via `analyzeMFT`'s CSV output. Since `analyzeMFT` does not export the Log File Sequence Number field, the raw `$MFT` file was parsed directly: each MFT record occupies a fixed `1024` bytes, with the LSN stored as an 8-byte little-endian unsigned integer at offset `0x08` within the record header. Seeking to `180174 * 1024 + 8` and reading the resulting 8 bytes produced an LSN of `1276820064`.

```bash
$ grep -ia "fruit_Assortment" /tmp/mft.csv                            
180174,Valid,In Use,File,5,179861,0,fruit_Assortment.jpg,,2020-04-12T02:14:46.234Z,2020-04-12T02:14:46.655Z,2020-04-12T02:14:30.983Z,2020-04-12T02:28:19.235Z,2020-04-12T02:14:46.234Z,2020-04-12T02:14:46.655Z,2020-04-12T02:14:30.983Z,2020-04-12T02:14:46.655Z,20bcbc0c-7c62-11ea-b942-000c29727385,00000080-0078-0000-0100-000000000400,00000000-0000-0000-a500-000000000000,00000040-0000-0000-0060-0a0000000000,True,False,True,False,False,True,False,False,False,False,False,False,False,[],None,,None,"{'name': 'Zone.Identifier', 'non_resident': False, 'content_size': 225, 'start_vcn': None, 'last_vcn': None}",None,None,None,None,None,None,None,,,,

$ python3 -c "
import struct
with open('\$MFT', 'rb') as f:          # raw \$MFT, binary
    f.seek(180174 * 1024 + 8)           # record 180174, 1024-byte records; LSN at +0x08
    data = f.read(8)                    # 8-byte \$LogFile sequence number
    lsn = struct.unpack('<Q', data)[0]  # little-endian uint64
    print('LSN:', lsn)
"
LSN: 1276820064
```

Q34- Jim has some dirt on the company stored in a `docx` file. Find it, the flag is the fourth secret, in the format of <"The flag is a sentence you put in quotes">. (Secrets, secrets are no fun)

Answer: `Customer data is not stored securely`

Reason: Recovery of deleted "company secrets" content was performed against `$RQ1FSDY.docx`, a recycled document recovered from `$Recycle.Bin/S-1-5-21-2446097003-76624807-2828106174-1003`, the SID folder previously associated with `hansel.apricot`. Extraction with `unzip` and `docx2txt` revealed a document titled "Fruit inc. company secrets," listing four bulleted items. The fourth secret reads: `Customer data is not stored securely`.

```bash
$ cp \$Recycle.Bin/S-1-5-21-2446097003-76624807-2828106174-1003/\$RQ1FSDY.docx /tmp #renamed to doc

$ unzip -l doc     
Archive:  doc
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2020-04-11 16:20   Document1/
     5319  2020-04-11 16:16   Document1/Content.xml
[...]

$ docx2txt Content.xml -
Fruit inc. company secrets
   * Tim is sleeping with his secretary
   * Miriam is copying designs from the iPhone
   * Suzy was only hired for her looks
   * Customer data is not stored securely 
```

Q35- In the company Slack, what is threatened to be deactivated if the user gets their email deactivated?

Answer: `kneecaps`

Reason: Analysis of Slack's local IndexedDB LevelDB store (`Users/hansel.apricot/AppData/Roaming/Slack/IndexedDB/https_app.slack.com_0.indexeddb.leveldb/000003.log`) using `strings` recovered rich-text message content surrounding a discussion of email deactivation. One message reads "And so do your kneecaps, well, as much as they do now" in direct response to reassurance that "your email definitely still works," implying that a threat to deactivate `kneecaps` accompanies any email deactivation.

```bash
$ strings ./Users/hansel.apricot/AppData/Roaming/Slack/IndexedDB/https_app.slack.com_0.indexeddb.leveldb/000003.log | grep 'text"' | grep -i deactivation -B 20 | tail -n 20
text"
text"5And so do your kneecaps, well, as much as they do now{
text"5And so do your kneecaps, well, as much as they do now"
type"   rich_text"
text"
text".Don't worry. Your email definitely still works{
text".Don't worry. Your email definitely still works"
type"   rich_text"
text"
text"
text"
type"   rich_text"
text"
type"   rich_text"
text"Ihttps://media.tenor.com/images/80705e271ed89afd3af976f37cd5e20d/tenor.gif{
text"
type"   rich_text"
text"
text"/So I'm hearing two email deactivation requested{
text"/So I'm hearing two email deactivation requested"
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Host Indicators | OS Build | `16299` (Windows 10 1709) |
|  | Computer Name | `DESKTOP-3A4NLVQ` |
|  | Machine SID | `S-1-5-21-2446097003-76624807-2828106174` |
|  | Processor Architecture | `AMD64` |
|  | DHCP Domain | `fruitinc.xyz` |
|  | Last DHCP IP | `192.168.2.242` |
| User Accounts | Total Users | `6` |
|  | Last Logged-On User | `jim.tomato` |
|  | suzy.strawberry RID | `1004` |
|  | admin Login Count | `10` |
| Browser Evidence | VSCO Girl Phone Search | `hansel.apricot` — Firefox `places.sqlite` |
|  | Flirting Admission Search (obfuscated) | `tim.apple` — "how do i nicely fire my stinky employee" |
|  | Hacking Tutorial Video | `jim.tomato` — `hxxps://www.youtube.com/watch?v=Y-CsIqTFEyY` |
| Recovered Documents | Secret CEO Plans | `Users/tim.apple/Documents/secret.odt` — 4 plans, incl. "Fire Jim Tomato" |
|  | Company Secrets Doc | `$Recycle.Bin/.../$RQ1FSDY.docx` — "Customer data is not stored securely" |
| Steganography | Embedded PNG (iPhone photo) | SHA-1 `537fe19a560ba3578d2f9095dc2f591489ff2cde` in `samplePhone.jpg` |
| Recycle Bin | Dog Photo | `hansel.apricot` — `$RGETALS.jpg` |
| Applications | LibreCAD Installer | Installed by `miriam.grapes` |
|  | Tor Browser Install Path | `C:\Program1` |
|  | Tor Browser Launch Count | `2` (jim.tomato) |
| Execution Evidence | 7zG.exe Last Run | `04/12/2020 02:32:09 UTC` |
|  | Firefox Highest Run Count | `21` — `FIREFOX.EXE-A606B53C.pf` |
| Persistence | admin Startup Item | `OneDrive` |
| Filesystem | MFT Entry Count | `219904` |
|  | fruit_Assortment.jpg LSN | `1276820064` |
| Communications | Slack Threat | "kneecaps" threatened re: email deactivation — `hansel.apricot` Slack IndexedDB |

# Lab Insights

- **Registry hives are the fastest path to host-level ground truth.** Nearly every foundational fact about this system (OS build, hostname, machine SID, architecture, DHCP domain/IP, startup persistence, last logged-on user) was answerable directly from SOFTWARE and SYSTEM hive keys via `reglookup`, without touching a single event log. When a question asks "what is the system's X," check the registry first — it's almost always faster and more authoritative than log parsing.
- **Filenames lie, magic bytes don't.** Multiple pieces of evidence in this case depended on ignoring the stated file extension or name entirely: a `.jpg` that was actually a 7z archive, a "sample phone photo" JPEG with a second PNG appended after it, and a Recycle Bin `.docx` that needed unzipping to reach its real XML content. Whenever a file sits somewhere it doesn't obviously belong (like an archive named to look like an image, hidden in Pictures), verify type with `file`/`binwalk` before trusting the name.
- **Corporate misconduct leaves a browser-shaped paper trail.** Nearly every "soft" HR/ethics finding in this lab (the CEO's plans, his admission of flirting, the stolen designs, insecure data handling) surfaced through search history or chat logs rather than technical artifacts — reinforcing that browser history and messaging app local storage (IndexedDB, SQLite) are just as central to insider-threat investigations as registry or MFT analysis, especially when the "attacker" is an employee acting in plain sight rather than an external intrusion.
- **Tooling friction is itself a forensic lesson.** A meaningful share of this investigation's time went into fighting broken/misnamed CLI tools (`evtx_dump` PATH collisions, a `python-evtx` package missing its own entry-point module, `analyzeMFT`'s ephemeral venv, a Prefetch parser hiding under an unexpected binary name). The practical takeaway: verify a tool's actual installed files (`pip show -f`, `dpkg -L`) before trusting its documented entry point, and don't assume a plausible-sounding package name is the right one.
- **Not every anomaly is evidence — verify before treating a signal as real.** The `binwalk` scan of the phone image initially looked like a false positive (a Zlib signature adjacent to a PNG header, which normally just reflects a PNG's own internal IDAT chunk) but turned out to be a genuinely appended second file. The inverse also applies for MFT record-size assumptions, which held here only because the file-size-to-record-count arithmetic came out even. Cross-check assumptions against independent evidence rather than accepting or dismissing an anomaly on pattern-matching alone.