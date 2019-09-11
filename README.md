# URL Analyzer
Firefox extension for dynamic analysis of malware

Demo: https://www.youtube.com/watch?v=90uszUgppFo&feature=youtu.be

## Overview 
URL Analyzer is a Mozilla Firefox extension, and it serves the purpose to analyze each and every URL a user is trying to access to using the browser. This extension basically analyzes URLs for malicious content, i.e. to prevent user from accidentally downloading any malicious content to his system. It checks urls in stages, if a user is trying to access a webpage, it checks if it contains some malicious link or not. If it being a download url, then it hooks the download to the Cuckoo sandbox for detonation, and gets a score, on the basis of which it alerts the user about it being malicious or not.

## Implementation 
It is a two stage process, first involving a user clicking on the extension from the browser tab, once done it checks for malicious content in the page being loaded. It extracts all the urls from the page, parses through them and sends each url to Virustotal to check if it contains any malicious content or not. Virustotal provides a public API for this purpose, where in, it takes a URL and has several antivirus engines working at the backend that checks the given URL against the database of known malicious domains. It then provides a report to the user stating all the antivirus engines it had used for scanning the URL and what have they detected. For this, first a request is sent to the Virustotal to scan a URL, corresponding to which a scan id is generated and sent to the user. Later, user calls another API to retrieve results pertaining to that scan id and represents results to the user. Even if a URL is found malicious by one engine, it alerts the user about it.

In the second stage, it checks for any file being downloaded to the system. It does so by pausing the download first, then it calls the Cuckoo API to check the URL, where in, it first downloads the file on the Cuckoo sandbox and then analyze it and collects comprehensive results based on what all the malware does while running in the isolated environment. It generates a score based on this and serves it along with the analysis report to the user. If the score is above 5, it means it lies in the malicious zone and cancels the download. However, if it is less than that it resumes the download as it is a benign file. For this, again first call to the API involves passing a URL and getting a task, id corresponding to it. It then checks continuously the status of that task, and if it comes ‘reported’, it requests for the report by calling the result API.

## Dependencies

1. Cuckoo Sandbox - 2.0.5

2. Virustotal API

3. Python - 2.7.14

4. Mozilla Firefox - 59.0.2 (64-bit) Future Work The extension involves installation of Cuckoo sandbox on the user’s system, which is a very tedious process as it requires several dependencies and configurations. However, if this is provided in a docker image, it eases the process of installation and configuration. Apart from the deployment issues, I would like behavioural analysis wherein, custom signatures could be created in Cuckoo which checks files against latest known malware behaviour. Also for Virustotal, current work involves using public API, which limits the number of requests a user can send for scanning per minute, however this can be replaced by using private api which allows unlimited no. of URLs that can be scanned for malicious content.

## References

1. http://docs.cuckoosandbox.org/en/latest/

2. https://developer.mozilla.org/en-US/docs/Web/JavaScript

3. https://www.virustotal.com/en/documentation/public-api/

4. http://cyfor.isis.poly.edu/69-fall_2017_digital_forensics_final_project_page.html

5. http://stackoverflow.com

6. https://en.wikipedia.org/wiki/Malware
