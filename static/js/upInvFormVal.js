$(document).ready(function() {
  // ensure user fills in at least one of the sharecount or moneyinvested inputs
$('#companyOfInterest').on('submit',function(){
  if($('#share_count').val() === '' && $('#money_invested').val() === ''){
    event.preventDefault();
    $('.msg').html('Please fill in either the number of shares you\'ve bought, or the amount of money invested');
  }
});
});