function replaceCompany(id){
  res = document.getElementById("company").value = id;
}
function getSuggestions() {

    let x = document.getElementById('company').value;
    console.log(x);
     url = `/get_matches/${JSON.stringify(x)}`;
    //console.log(x);
    axios.get(url)
    .then(function(response) {
       var matched_companies = JSON.stringify(response.data);
       availableTags = JSON.parse(matched_companies);
       console.log(JSON.parse(matched_companies));
       res = document.getElementById("result");
       res.innerHTML = '';
       let list2 = '';
       for (let k in availableTags) {
        //console.log(k + ' is ' + availableTags[k]);
        list2 += '<tr class =\"autocomplete-items\" onclick=\"replaceCompany(this.id)\" id='+k+'><td>' + k + ' - ' + availableTags[k] + '</td></tr>';
    }
       res.innerHTML = '<table id=\"tab\">' + list2 + '</table>';              
    })
    .catch(function(error) {
        console.log(error);
    }); 
}