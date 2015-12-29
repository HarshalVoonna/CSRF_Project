var CSRFDetector = {

  knownTokenFormats: {
  //Include csrf_token
      "names":["fb_dtsg", "csrftoken", "token","csrf","secTok", "[0-9a-f]{32}"],
      "formats": ["[A-Za-z0-9]{10,}"]
  },
  
  startDetection: function(){
    console.log("[CSRF Detector] Detection started.");
    
	var forms = document.getElementsByTagName('form');
    
	for (var i = 0; i < forms.length; i++) {
    
	if( ! (input = this.containsCSRFToken(forms[i])) ) {
        console.log("[CSRF Detector] Form "+forms[i].getAttribute("name")+" may not be protected");
		forms[i].style.backgroundColor ="red";
      }
    else {
        console.log("[CSRF Detector] Form "+forms[i].getAttribute("name")+" is protected by input element "+input.getAttribute("name"));
		forms[i].style.backgroundColor ="lightgreen";
		}
    }
  },
  
  
  containsCSRFToken: function(form) {    
  
	var inputs = form.getElementsByTagName("input");
    
	for (var i = 0; i < inputs.length; i++) {
   
      if( inputs[i].getAttribute("type") != "hidden" ) continue;   
  
      var name = inputs[i].getAttribute("name");
      var value = inputs[i].getAttribute("value");

      for (var j=0; j < this.knownTokenFormats.names.length; j++) {
    
		var pattern1 = new RegExp("^"+this.knownTokenFormats.names[j]+"$");
        
		console.log("[CSRF Detector] Matching name "+name+" to "+this.knownTokenFormats.names[j]);
        
		if( pattern1.test(name) ) return inputs[i];
      
	  }
      
      for (var j=0; j < this.knownTokenFormats.formats.length; j++) {
      
	  var pattern2 = new RegExp(this.knownTokenFormats.formats[j]);

		console.log("[CSRF Detector] Matching value "+value+" to "+this.knownTokenFormats.formats[j]);
    
		if( pattern2.test(value) ) return inputs[i];
      
	  }
      
    }
    
    return false;
  } 
}

CSRFDetector.startDetection();