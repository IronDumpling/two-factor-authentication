#Chuyue Zhang, 1005728303, zhangchuyue.zhang@mail.utoronto.ca

#Da Ma, 1006353474, da.ma@mail.utoronto.ca

# Part 1
## Part 1.1

## Part 1.2

# Part 2
## Part 2.1
Follow the instructions on the handout, I first run setup the venv of Python3 using setup.sh. Then I ran the mobile_mfa.py to see the QR Code and move to the next part.

## Part 2.2
To make the simulated login successful, the script must first create a new account, and a authenticator. The script needs to check the authenticator status.
During this process, the user needs to use BioConnect to scan the QR Code and enroll at least one of the Bio information. Then the user needs to 
fill in the simulated user name and password. The script then needs to send a POST verification request and get the verification status every second. 
During the waiting time, the status would be "pending". Thus the BioConnect would send a Verification request to the user. After the user verifies it, 
the verification status becomes "success".
