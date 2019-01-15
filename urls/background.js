var allLinks = [];
var visibleLinks = [];

//Listener when extension is clicked
browser.browserAction.onClicked.addListener(function(tab) {
  browser.tabs.query({active: true, currentWindow: true}, function(tabs) {
    var activeTab = tabs[0];
    browser.tabs.sendMessage(activeTab.id, {"message": "enabled"});
  });
});

//Virustotal - send url for analysis
function checkLinks() {
  for (var link in visibleLinks) {
      mylink = visibleLinks[link];
      var scan_id;
      var checkgoogle = mylink.includes("google");
      if (checkgoogle == false) {
      var xhrobj = new XMLHttpRequest();
      xhrobj.open("POST", 'https://www.virustotal.com/vtapi/v2/url/scan');
      var formData1 = new FormData();
      formData1.append("url",mylink);
      formData1.append("format",'json');
      formData1.append("apikey",'e92f6b6a495dc721b65c8e3c27fe16bf43e45980c1bfbbddeb414df10e3cfd03');
      xhrobj.onreadystatechange = function() {
              if(xhrobj.readyState == XMLHttpRequest.DONE && xhrobj.status == 200) {
                        var myresponsejson1 = JSON.parse(this.responseText);
                        alert(JSON.stringify(myresponsejson1));
                        scan_id = myresponsejson1.scan_id;
                        setTimeout(fetchReport(mylink, scan_id), 9000);
                        alert("1 response... ")
                        alert(scan_id);
                    } 
                 }
      xhrobj.send(formData1); 
      //alert("1 request sent")      
    }
  }
}

browser.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
     //Monitor downloads, hook url to the Cuckoo sandbox for analysis  
     if( request.message === "monitor_downloads" ) {
      browser.downloads.onCreated.addListener(function(downloadItem) {
      browser.downloads.pause(downloadItem.id);
      download_url = downloadItem.finalUrl;
      download_id = downloadItem.id;
      var opt1 = {
                  type: "basic",
                  title: "URL Analyzer",
                  message: "Download paused and sent for Analysis",
                  iconUrl: "icons/url-48.png",
                  progress: 20
                };
      browser.notifications.create(opt1);
      var xhr = new XMLHttpRequest();
      xhr.open("POST", 'http://localhost:8090/tasks/create/url',true);
      var formData = new FormData();
      formData.append("url",download_url);
      xhr.onreadystatechange = function() {
              if(xhr.readyState == XMLHttpRequest.DONE && xhr.status == 200) {
                        var myresponsejson = JSON.parse(xhr.responseText);
                        myid = myresponsejson.task_id;
                        setTimeout(reporting(myid, download_url, download_id), 4000);
                        
              }
      }
      xhr.send(formData); 
      });
    }
    // Collect URLs from a webpage for analaysis against virustotal  
    if( request.message === "malware_protection" ) {
       browser.windows.getCurrent(function (currentWindow) {
          browser.tabs.query({active: true, windowId: currentWindow.id},
                                function(activeTabs) {
                           browser.tabs.executeScript(
                                  activeTabs[0].id, {file: 'extract_links.js', allFrames: true});
                      });
      });        
    }
    if(request.message === "send_link_call"){
       var flag = true;    
       for (var index in request.links) {
             for(var y in allLinks)
                 { 
                   if(allLinks[y] === request.links[index])
                       {
                           flag = false;
                           break;
                       } 
                 }
             if (flag === true)
                 {
                   allLinks.push(request.links[index]); 
                   console.log("adding below url ...");
                   console.log(request.links[index]);     
                 }
       }
       allLinks.sort();
       visibleLinks = allLinks;
       checkLinks();        
    }  
  }
);

//Fetch results from virustotal
function fetchReport(myLink, scan_id){
    
    if (scan_id !== 'undefined' && scan_id !== null){
            alert("scan id not null")
            alert(scan_id);
            var xhrobj1 = new XMLHttpRequest();
            xhrobj1.open("POST", 'https://www.virustotal.com/vtapi/v2/url/report');
            var formData2 = new FormData();
            formData2.append("resource",scan_id);
            formData2.append("format",'json');
            formData2.append("apikey",'e2d16d1525fc8e9cf957d858b79d5a11196135d9b664330db4c25eb5b1ec7051');
            xhrobj1.onreadystatechange = function() {
            if(xhrobj1.readyState == XMLHttpRequest.DONE && xhrobj1.status == 200) {
                    alert("2 response received ....");
                    var myresponsejson2 = JSON.parse(this.responseText);
                    var detected = "";
                    alert(JSON.stringify(myresponsejson2));
                    //myresponse = xhr.responseText;
                    // Use 'this' keyword everywhere if this doesnt work correctly
                    //alert(this.responseText);
                    scans = myresponsejson2.scans;
                    positives = myresponsejson2.positives;
                    total = myresponsejson2.total;
                    for (var key in scans){
                            alert(key + " -> " + scans[key]['detected']);
                            if (scans[key]['detected'] == true){
                                detected += key 
                                detected += " "
                            }
                    }
                    if (detected !== "") {
                       var opt3 = {
                                   type: "basic",
                                   title: "URL Analyzer - Found Suspicios URL",
                                   message: "The URL- '"+myLink+"' was found  malicious by - " + detected,
                                   iconUrl: "icons/url-48.png"
                                  };
                       browser.notifications.create(opt3);
                } else{
                    var opt5 = {
                                   type: "basic",
                                   title: "URL Analyzer: This URL is benign!",
                                   message: "Found "+ positives+" positives in "+total+" antivirus engines",
                                   iconUrl: "icons/url-48.png"
                                  };
                       browser.notifications.create(opt5);
                }
            }
        }
          xhrobj1.send(formData2); 
          alert("2 request sent")  
    }
    
}

//Fetch results from Cuckoo 
function reporting(myid, download_url, download_id) {
      var myviewurl = 'http://localhost:8090/tasks/view/' + myid
                        var xhr1 = new XMLHttpRequest();
                        xhr1.open("GET", myviewurl, true);
                        xhr1.onreadystatechange = function() {
                              if(xhr1.readyState == XMLHttpRequest.DONE && xhr1.status == 200) {
                                    var myresponse1json = JSON.parse(xhr1.responseText);
                                    var mystatus = myresponse1json.task.status;
                                    if (mystatus == 'reported') {
                                              var xhr2 = new XMLHttpRequest();
                                              var myreporturl = 'http://localhost:8090/tasks/report/' + myid
                                              xhr2.open("GET", myreporturl, true);
                                              xhr2.onreadystatechange = function() {
                                                    if(xhr2.readyState == XMLHttpRequest.DONE && xhr2.status == 200) {
                                                            var myreport = JSON.parse(xhr2.responseText);
                                                            myscore = myreport.info.score;
                                                            if (myscore < 5) {
                                                                    browser.downloads.resume(download_id);
                                                                    var opt4 = {
                                                                                  type: "progress",
                                                                                  title: "URL Analyzer",
                                                                                  message: "Analysis passed with score "+myscore + ", download resumed",
                                                                                  iconUrl: "icons/url-48.png",
                                                                                  progress: 100
                                                                                };
                                                                    browser.notifications.create(opt4);
                                                            }
                                                            else {
                                                                    browser.downloads.cancel(download_id);
                                                                    var opt2 = {
                                                                                  type: "progress",
                                                                                  title: "Download Monitor",
                                                                                  message: "Download is malicious with score "+myscore+ "!!",
                                                                                  iconUrl: "icons/url-48.png",
                                                                                  progress: 100
                                                                                };
                                                                    browser.notifications.create(opt2);
                                                            }  
                                                    }
                                              }
                                              xhr2.send(null);
                                      }
                                      else {
                                              reporting(myid, download_url, download_id);
                                      }
                                  }
                        }
                        xhr1.send(null);
}