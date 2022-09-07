// when a selection is clicked, automatically submit the form
function replaceCompany(id){
  var fileName = location.pathname;
  fileName = fileName.slice(0,-1);
  fileName = fileName.split("/").pop();
  res = document.getElementById("company").value = id;
  if(fileName === 'stock_prices'){
    document.getElementById("companyOfInterest").submit();
  }  
}

// displays the selection recommendations to the user as a table
function getSuggestions() {
    // get current value in text box, and form url for backend
    let x = document.getElementById('company').value;
     url = `/get_matches/${JSON.stringify(x)}`;
    axios.get(url)
    // get response, and add each suggestion to a row of a table, and display to user
    .then(function(response) {
       var matched_companies = JSON.stringify(response.data);
       availableTags = JSON.parse(matched_companies);
       res = document.getElementById("result");
       res.innerHTML = '';
       let list2 = '';
       for (let k in availableTags) {
        list2 += '<tr class =\"autocomplete-items\" onclick=\"replaceCompany(this.id)\" id='+k+'><th class=\"auto\">' + k + ' - ' + availableTags[k] + '</th></tr>';
    }
       res.innerHTML = '<table id=\"tab\">' + list2 + '</table>';              
    })
    .catch(function(error) {
        console.log(error);
    }); 
}