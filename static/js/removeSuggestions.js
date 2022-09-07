$( document ).ready(function() {
  // when text box is clicked off, check if a suggestion is clicked, if not, remove them from the screen
  $('#company').blur(function() {
    window.onclick = e => {
      if (e.target.tagName != 'TD'){
        $('#result').html('');
      }
    }
  });
});