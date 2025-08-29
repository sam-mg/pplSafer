# 
sudo apt install clamav clamav-daemon -y --fix-missing

# 
sudo killall freshclam
sudo freshclam

clamscan <apk_file> --log=output.log

# Sample Output:
# ┌──(sam-mg㉿Kali-Linux)-[~]
# └─$ clamscan APKs/Legit/Mulyan.apk --log=output.log
# Loading:     7s, ETA:   0s [========================>]    8.71M/8.71M sigs       
# Compiling:   2s, ETA:   0s [========================>]       41/41 tasks 

# /home/sam-mg/APKs/Legit/Mulyan.apk: OK

# ----------- SCAN SUMMARY -----------
# Known viruses: 8708228
# Engine version: 1.4.3
# Scanned directories: 0
# Scanned files: 1
# Infected files: 0
# Data scanned: 36.87 MB
# Data read: 6.70 MB (ratio 5.50:1)
# Time: 13.558 sec (0 m 13 s)
# Start Date: 2025:08:27 21:09:03
# End Date:   2025:08:27 21:09:16
                                                                                        
# ┌──(sam-mg㉿Kali-Linux)-[~]
# └─$ cat output.log                                 

# -------------------------------------------------------------------------------



# ----------- SCAN SUMMARY -----------
# Known viruses: 8708228
# Engine version: 1.4.3
# Scanned directories: 0
# Scanned files: 1
# Infected files: 0
# Data scanned: 36.87 MB
# Data read: 6.70 MB (ratio 5.50:1)
# Time: 13.558 sec (0 m 13 s)
# Start Date: 2025:08:27 21:09:03
# End Date:   2025:08:27 21:09:16