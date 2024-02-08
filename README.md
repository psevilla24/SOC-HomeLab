# Security Operation Center (SOC) Home Lab

## Objective

The goal of the SOC HomeLab project was to create a controlled setting for simulating and identifying cyber threats. Its main objective was to ingest and examine logs using a Security Information and Event Management (SIEM) system, thereby producing simulated telemetry to replicate real-world attack situations. This interactive experience was crafted to enhance comprehension of network security, attack methodologies, and defensive tactics.

### Skills Learned

- Developing a solid grasp of SIEM concepts and their real-world applications.
- Acquiring proficiency in the analysis and interpretation of network logs.
- Cultivating the ability to recognize and generate attack signatures and patterns.
- Gaining a better understanding of network protocols and security vulnerabilities.
- Setting up and configuring virtual machines (VMs) for various operating systems, creating a mini network environment for testing and experimentation.
- Nurturing critical thinking and problem-solving skills within the cybersecurity domain.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Virtualization like VirtualBox A virtualization platform for hosting virtual machines (VMs) to simulate network environments.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc
Download and set up virtual box 
![Screenshot 2024-02-07 at 1 09 11 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/ce2ce583-7101-4710-ade6-ae3354e84ac3)

Download security onion and configure
![Screenshot 2024-02-07 at 1 21 49 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/5da94fcf-7513-4fe9-a8ad-4da4afa935ac)

Go to Powershell and type Get-Filehash  plus file name to ensure file integrity

![Screenshot 2024-02-07 at 1 29 22 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/14a9e399-f3c9-4b65-be5f-8416482b1fb6)
![Screenshot 2024-02-07 at 1 30 39 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/048c81a1-d55d-4ded-8736-b010b76332c4)

Spin up Virtualbox and click new then Follow the prompt, Name the the VM, pick a storage to store files, and find the iso file for security onion and
I will keep the installation as default.

![Screenshot 2024-02-02 at 7 38 25 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/ff3dc19b-8983-463f-b2a4-a8711a839b22)

I will configure Security Onion to 16 gigs of RAM, 2 CPU, and 200 gigs of storage to accommodate Security onions features

![Screenshot 2024-02-02 at 7 39 45 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/19aae1c6-1e7a-4a14-95d7-cf85f5f4c7cf)
![Screenshot 2024-02-02 at 7 42 30 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/14b65b34-62ef-4b81-a650-050b2c49f2e2)

Security onion will start and we will be presented with these options, Click yes to proceed.

![Screenshot 2024-02-02 at 7 43 20 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/6a969ee9-f65e-47f4-962e-c823890fc5f9)

Add Username and Password for Security Onion

![Screenshot 2024-02-02 at 7 44 31 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/ec2a25f3-dda8-4b06-8178-b5781b026e5a)

Installation completed please reboot, Now we need to sign in with the credentials that we made for Security Onion 

![Screenshot 2024-02-02 at 7 46 16 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/794ccfb3-329f-434f-b076-1e13c1ce8437)

The welcome page of Security Onion will be presented, click yes to proceed

![Screenshot 2024-02-02 at 7 50 56 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/ad70dedd-acad-4efc-9033-a403896438fe)

Security Onion setup option, we will do standard installation for this and Agree on terms and agreements

![Screenshot 2024-02-02 at 7 52 05 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/fff5adcf-883f-4aef-ad8d-4aa84b5c145a)

Next, we will select Stand Alone option

![Screenshot 2024-02-02 at 7 53 24 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/8c2dc365-f8d0-4ac0-b067-73745be15c3d)

For network settings we will select the standard option to connect online, Air gap means no connection to the internet

![Screenshot 2024-02-02 at 7 53 51 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/6bbda60c-4025-4bc3-8c18-379cd8599966)

Designate the hostname for employing Security Onion.

![Screenshot 2024-02-02 at 7 55 37 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/c22bc509-ad51-4674-b2ff-c5651cb25074)

In our lab environment, we'll maintain the Security Onion setup as it is. However, in a production environment, I would alter the hostname to prevent potential conflicts.

![Screenshot 2024-02-02 at 7 55 58 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/9699b190-cee3-42c4-b438-08e99a6fa5a0)

After selecting our network interface I highly recommend setting up a static IP address 

![Screenshot 2024-02-02 at 8 01 52 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/19dddf7c-7caa-424e-a452-52881f2d5d3a)

We will set 192.168.100.40/24 for our static IP

![Screenshot 2024-02-02 at 8 02 53 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/76e5b916-bb67-4a2e-a90d-9725b3c5ea66)

Set up Gateway 192.168.100.1 and the DNS servers you wish to use, in this case, I will use Google DNS 8.8.8.8.8.8.4.4

![Screenshot 2024-02-02 at 8 04 18 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/b58d4b4e-4f7e-4391-97b4-90860f46fecd)

We will connect directly and no proxy

![Screenshot 2024-02-02 at 8 04 40 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/b161f110-c19b-47ba-9135-89dae046ca65)

We'll keep the docker IP range default 

![Screenshot 2024-02-02 at 8 05 28 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/044bb3ff-38a4-4125-a0de-505c5266b156)

Please provide an email address for Elasticsearch and Kibana. Note that it does not need to be a genuine email. We'll use bob@test.com.

![Screenshot 2024-02-02 at 8 06 40 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/def1b5e8-2cd6-496b-b354-b343d5273976)

We’ll use IP for this option

![Screenshot 2024-02-02 at 8 07 14 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/60e04c5d-6020-494f-84bd-915dbb4451c3)

Review the summary options, Then let's visit the IP that we set up for Security Onion on the web browser

![Screenshot 2024-02-02 at 8 10 07 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/552cce7d-bb36-4ac1-ace2-6df57762211a)

If dropped traffic occurs, adjust the IP table rule to permit inbound communication originating from the listed IP address and specify the TCP protocol.

![Screenshot 2024-02-02 at 8 12 04 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/817b30be-bda6-448b-b8f2-664c1193ee9b)

Retry the web browser again and it should work, Log in to Security Onion

![Screenshot 2024-02-02 at 8 12 57 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/a872cb0b-9f65-4e56-854f-8d466653d8f2)

And we're in! Next, we'll begin ingesting our first PCAP file.

![Screenshot 2024-02-02 at 8 13 38 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/349fd16a-7400-4c53-924a-c3f905b03ecd)

On the Security Onion server, execute 'ls' to view the existing directories. Then, enter 'mkdir temp' to generate a new directory.

![Screenshot 2024-02-02 at 8 14 51 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/b7bda3a3-02fe-4ac6-9b38-448fe2237cfe)

Let's navigate to MalwareTrafficAnalysis.net and utilize the spoonwatch.pcap file.

![Screenshot 2024-02-02 at 8 18 39 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/b03b652b-6047-4dd6-8dd3-75039783f9e9)

To obtain the pcap file, we'll utilize wget along with the URL of the pcap file and Unzip the pcap file

![Screenshot 2024-02-02 at 8 19 20 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/3509f81a-63bc-4711-8b14-4a323ac7e154)
![Screenshot 2024-02-05 at 5 31 34 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/3a0a9061-1bad-40cb-bc63-0936c40d4721)

Let's initiate the process of importing this pcap file into our Security Onion.

![Screenshot 2024-02-05 at 5 33 19 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/351a28d3-68d1-4e15-b220-8d2a273632e3)

Suricata and Zeek will commence analyzing the traffic. Please ensure that the time reflects around 2022 and not the last 24 hours, as our file is dated around that time. Scroll down to observe the types of events present within our instance.

![Screenshot 2024-02-05 at 5 38 27 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/1331fd14-e1a6-47d1-a807-041cffcad328)

 I can see that Zeke has a couple of log files here there's Zeke.conn and RPC DNS Kerberos SSL file so it has a couple of logs for us to take a look at, I also noticed that Suricata has generated some alerts. You can see them in the "Suricata alert" field.
 
 ![Screenshot 2024-02-05 at 5 43 21 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/df37f192-25f3-4d8c-9043-956f73eb3f3e)

  Scrolling to the bottom, we have some IP addresses, destination IP addresses, ports, and Geo organization names as well.

![Screenshot 2024-02-05 at 5 52 17 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/d9bc0114-a9f2-49f3-beba-3ba4c39e633c)

  This pretty much confirms that our pcap has been successfully imported into our instance. Take a look at the bottom where we have a signature hunting suspicious zipped file named in an outbound post request. Additionally, at the bottom, there seems to be malware. It appears to be a stealer of some sort. Currently, we don't have much information, but we do have the traffic flow documented.

![Screenshot 2024-02-05 at 5 56 20 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/4c65a608-63b7-4ba9-8988-3638c71111be)

You can assign tasks to other analysts to avoid duplicate work.

![Screenshot 2024-02-07 at 6 39 01 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/04870f42-c9e2-4ed0-9bdf-f252fc788797)

We can see five alerts now. Next, to assign an alert to yourself, you'll need to click on the blue triangle icon. This will enable you to escalate it to a new case.

![Screenshot 2024-02-05 at 6 01 18 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/1c8ad473-2fcc-4c95-a8c7-bc3073489e8d)

To investigate the signature further, we can perform some OSINT (Open Source Intelligence) to understand what exactly the signature is looking for. For example, with this HTTP POST, we can click on "Hunt" on the left-hand side. This will enable us to start querying for data.

![Screenshot 2024-02-05 at 6 12 31 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/55796086-4234-44aa-92d9-8fe18e8a7fac)

When we click on the signature of interest, I'll select the magnifying glass icon. This allows me to filter for only this value. Then, I'll sort the time, and now we can see the earliest event. This is something that we need to take note of, as well as the source IP ending in 216 communicating outbound towards this IP. Again, I'll keep note of all of these. We can also take a look at some of the OSINT tools. In this case, I used the AbuseIPDB tool to check the reputation score of this IP. Now, it's been reported six times, and we can see that it's coming from a country in the Netherlands. If we scroll down and take a look at why it was being reported, we find a couple of SMTP blocks indicating it has been banned for spam. So, we know that this IP was used for nefarious purposes once upon a time. If we take a look at VirusTotal, it's reported as malware. Going into details, we could see that it had been listed under Malware Bazar, which is a database full of malware.

![Screenshot 2024-02-05 at 6 14 09 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/c7ab8bc8-0174-4d71-a7bd-cae9c81448a5)
![Screenshot 2024-02-05 at 6 14 53 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/1ae6f8a9-513c-4994-805e-f5bb5585bf5d)
![Screenshot 2024-02-05 at 6 18 14 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/71c07087-9d84-47a7-9d02-92f62a5bf673)
![Screenshot 2024-02-05 at 6 20 54 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/797f5f4d-a6b6-45e0-9bbb-d8a976002a65)
![Screenshot 2024-02-05 at 6 23 56 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/e1d7a9df-2c37-426b-9a92-8802322e9a1f)

As we scroll to the right, we observe a network Community ID. This ID facilitates the correlation of events between Suricata and Zeek. By searching for this Community ID, we may retrieve traffic associated with the POST request or any missed file downloads. Clicking on the Community ID and conducting a targeted search can help. Upon scrolling up, you'll find the Community ID listed under the query. Note that the Community ID is enclosed in quotation marks.

![Screenshot 2024-02-05 at 6 24 22 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/d5525e5f-50c8-4921-92f1-a2760be900c7)
![Screenshot 2024-02-05 at 6 53 03 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/b57b3057-9020-4169-90ee-8f6b293f7068)

Creating a timeline is extremely important during an investigation. Focusing solely on a single artifact isn't sufficient. It's crucial to paint a comprehensive picture of the events. A timeline allows us to illustrate exactly what occurred during that time, helping to craft a cohesive narrative of the incident. Also, keep the following five questions in mind: who, what, when, where, and why. Sometimes, consider how as well. These questions enable you to ask investigative questions to hopefully answer those five W's, providing clarity and depth to your investigation.

Upon simply searching the community ID, it provided me with a variety of rule names. We observe that there are four alerts related to this community ID, and on the left, you can see a count, indicating how many times the signature triggered. Let's make a note of the earliest time this activity occurred. Following this chain, we notice a policy PE exe alert right after this POST pattern. This suggests that something was likely downloaded from this web server. Just to confirm, if you look at the bottom again, right below that alert, you'll see an ET hunting suspicious dotted quad host MZ response. This simply means that a file, such as an executable or a DLL file, has been downloaded from an IP address.

![Screenshot 2024-02-05 at 7 01 18 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/426cd883-9492-4c52-a837-64df7c9d8f7f)

This website contains a wealth of information about file signatures, also known as file headers. File headers constitute the makeup of a file. When you download something that claims to be a PNG file, you examine the file header to determine whether it truly is a PNG file. For instance, if you were to open a PNG file in a hex editor, you would expect to see specific bytes. If these bytes match, you can confidently identify it as a PNG file. Now, if I search for the following header, the MZ header, you'll find that the beginning bytes are 4D 5A. What types of files have this file signature or file header? Some of them include .d, .drv, .exe, and many more. This is why I mentioned that when you're analyzing the signature, it's likely that either an executable or a DLL file was downloaded, as it mentioned "MZ".

![Screenshot 2024-02-05 at 7 06 12 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/ba3b73ce-fe07-4fa8-94b1-874a4086d3f5)
![Screenshot 2024-02-05 at 7 08 21 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/4022a6d2-2585-411c-a3c0-4bf077850424)

Returning to our Security Onion, we can expand the signature to gather additional information. Now, if you scroll down, you'll notice that it begins with an MZ header. However, if we examine the content type, it indicates that it's an image/jpeg. But that's not accurate. As you recall from the site listing file signatures, if it were indeed a JPEG file, we would expect to see a different header. Instead, going back to our Security Onion, we observe the MZ header, indicating that it's likely not a JPEG file but rather an executable file.

![Screenshot 2024-02-05 at 7 15 37 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/660d4244-209c-4fb2-b49d-1476fe45800a)

At the bottom, we have the rule which details how the rule is created. This post pattern request, which corresponds to the initial rule we observed, shows us how it's crafted right here. By examining the rule, we can determine the pattern that it's looking for. Upon inspecting the details, I can see that the flow requires it to be established to the server, the HTTP method is post, and the HTTP header content includes the pattern "boundary=". So, if the traffic contains this specific boundary string in the HTTP header, that's why this signature triggered. Additionally, we can see the references along with the MD5 hash, which is quite interesting. Now, I have a clear understanding of what they are trying to detect and why that signature triggered. Moving to the next page, it appears to be the same or similar signatures that are triggering, and they're communicating with the same IP address again. This should be expected because we are filtering by Community ID

![Screenshot 2024-02-06 at 12 09 54 PM](https://github.com/psevilla24/SOC-HomeLab/assets/86266429/b61c0cea-a4e6-4d21-ac30-8394967d1dd7)





























































 
































































































Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*
