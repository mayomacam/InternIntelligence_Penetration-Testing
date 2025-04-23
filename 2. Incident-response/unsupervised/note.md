# Sherlock Scenario

The incident happened around 4:30 PM on Friday, "The Last day of the week" at the Accounts/Marketing department of "Finance XYZ" company. There weren't many people in the department, and the remaining were not paying much attention to their surroundings as they were getting ready to head home. After the weekend on Monday while reviewing the security cam footage member of an IT team saw "Eddie" a new intern in the Accounts/Marketing department, plugging a USB into an unauthorized computer (containing sensitive financial and marketing documents), interacting with computer and unplugging the USB before heading out. As the incident happened 2 days ago, and not having enough knowledge of what Eddie did the security team use caution while asking around and gathering intel to avoid causing suspicion. The only information they were able to find out was that Eddie had a "Toshiba" USB. You are provided with a partial image of the “unauthorized computer" as well as a list of important documents, to investigate what he did and if he stole something sensitive or not?

---

# Find out the time zone of victim PC. (UTC+xx:xx)
09:03:44.460977	2024-Feb-15 / Asia/Tashkent
The system's current time zone is UTC-05:00.
If daylight saving time becomes active, the offset would adjust to UTC-04:00, as calculated using the DaylightBias.


# Employees should be trained not to leave their accounts unlocked. What is the username of the logged in user?
MrManj

# How many USB storage devices were attached to this host in total?
7
```
##?#STORAGE#Volume#_??_USBSTOR#Disk&Ven_VendorCo&Prod_ProductCode&Rev_2.00#4509611187672529927&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{6ead3d82-25ec-46bc-b7fd-c1f0df8f5037} 
##?#SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_VendorCo&Prod_ProductCode&Rev_2.00#4509611187672529927&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{6ac27878-a6fa-4155-ba85-f98f491d4f33} 
##?#STORAGE#Volume#_??_USBSTOR#Disk&Ven_VendorCo&Prod_ProductCode&Rev_2.00#4509611187672529927&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
##?#STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP#50E549C6930DEF81295A9D24&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{7f108a28-9833-4b3b-b780-2c6b5fa5c062}
##?#STORAGE#Volume#_??_USBSTOR#Disk&Ven_VendorCo&Prod_ProductCode&Rev_2.00#4509611187672529927&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{7f108a28-9833-4b3b-b780-2c6b5fa5c062}
~##?#USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP#50E549C6930DEF81295A9D24&0#{7fccc86c-228a-40ad-8a58-f590af7bfdce}
```

# What is the attach timestamp for the USB in UTC?
2024-02-23 11:37:50

# What is the detach timestamp for the USB in UTC?
2024-02-23 11:39:12

# Which folder did he copy to the USB?
Documents

# There were subfolders in the folder that was copied. What is the name of the first subfolder? (Alphabetically)
Business Proposals

# Eddie opens some files after copying them to the USB. What is the name of the file with the .xlsx extension Eddie opens?
Business Leads.xlsx

# Eddie opens some files after copying them to the USB. What is the name of the file with the .docx extension Eddie opens?
Proposal Brnrdr ltd.docx

# What was the volume name of the USB?
\??\Volume{4be283e5-d201-11ee-b920-000c298241c9}
TOSHIBA TransMemory USB Device ( from usbstor )

# What was the drive letter of the USB?
E / F

# I hope we can find some more evidence to tie this all together. What is Eddie's last name?

# There was an unbranded USB in the USB list, can you identify it's manufacturer’s name?
sony
##?#SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP#50E549C6930DEF81295A9D24&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{6ac27878-a6fa-4155-ba85-f98f491d4f33} ( 13.png, inside event log)









# files 
## original files
file:///C:/Users/MrManj/Documents/Business%20Proposals/Proposal%20Brnrdr%20ltd.docx
file:///C:/Users/MrManj/Documents/Business%20Proposals/Proposal%20Lg-Arc%20Inc.docx
file:///C:/Users/MrManj/Documents/Business%20Proposals/Proposal%20NG%20Garna%20corp.docx
file:///C:/Users/MrManj/Documents/External%20Finance/Current%20Clients.xlsx
file:///C:/Users/MrManj/Documents/Important%20docs/Business%20Leads.xlsx
file:///C:/Users/MrManj/Documents/Internal%20Finance/Internal%20Accounts.xlsx


# copy to usb files and opened to see (copy all 6 but check for 2)
file:///E:/Documents/Important%20docs/Business%20Leads.xlsx
file:///E:/Documents/Business%20Proposals/Proposal%20Brnrdr%20ltd.docx
