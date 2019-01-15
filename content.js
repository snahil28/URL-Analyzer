browser.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    alert("URL Analyzer enabled")  
    if( request.message === "enabled" ) {
      var firstHref = $("a[href^='http']").eq(0).attr("href");
      browser.runtime.sendMessage({"message": "monitor_downloads", "url": firstHref});
      browser.runtime.sendMessage({"message": "malware_protection", "url": firstHref});
    }
  }
);