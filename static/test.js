$(document).ready(function() {
  // listen to when the form to add a chore is completed  
  $(document).on('keyup','#company', function(){
    var x = $('#company').val();
    console.log(x);
    $.post('.', {'comp' : x}, 
    function(returnedData){
         //console.log(returnedData);
});
  }); 
});