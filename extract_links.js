// Fetches all urls from a webpage
var links = [].slice.apply(document.getElementsByTagName('a'));
links = links.map(function(element) {
  var href = element.href;
  var hashIndex = href.indexOf('#');
  if (hashIndex >= 0) {
    href = href.substr(0, hashIndex);
  }
  return href;
});
links.sort();
// Remove duplicates and invalid URLs.
var kBadPrefix = 'javascript';
for (var i = 0; i < links.length;) {
  if (((i > 0) && (links[i] == links[i - 1])) ||
      (links[i] == '') ||
      (kBadPrefix == links[i].toLowerCase().substr(0, kBadPrefix.length))) {
    links.splice(i, 1);
  } else {
    ++i;
  }
}

//browser.runtime.sendMessage(links);
browser.runtime.sendMessage({"message": "send_link_call", "links": links});
//browser.extension.sendRequest(links);