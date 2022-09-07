$(document).ready(function() {
  // don't allow user to press enter to submit form
  $(window).keydown(function(event){
    if(event.keyCode == 13) {
      event.preventDefault();
      return false;
    }
  });
});