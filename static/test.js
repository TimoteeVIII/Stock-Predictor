function myFunction(id){
  res = document.getElementById("company").value = id;
}
function getRandomNumber() {

    let x = document.getElementById('company').value;
    console.log(x);
    /* const request = new XMLHttpRequest();
    request.open('POST',`/api/datapoint/${JSON.stringify(x)}`);
    request.send(); */
     url = `/api/datapoint/${JSON.stringify(x)}`;

    axios.get(url)
    .then(function(response) {

        // The data will all be returned as a JSON object
        // We can access the data by using the data property of the response object

       // document.getElementById('randomNumberDiv').innerHTML = response.data.random_number;
       // document.getElementById('doubleRandomNumberDiv').innerHTML = response.data.double_random_number;
       // document.getElementById('serverTimeDiv').innerHTML = response.data.timestamp;
       var matched_companies = JSON.stringify(response.data);
       availableTags = JSON.parse(matched_companies);
       console.log(JSON.parse(matched_companies));

       res = document.getElementById("result");
       res.innerHTML = '';
       //let list = '';
       let list2 = '';
       for (let k in availableTags) {
        console.log(k + ' is ' + availableTags[k]);
        //list += '<li class=\"autocomplete-items\" onclick=\"myFunction(this.id)\" id='+k+'>' + k + ' - ' + availableTags[k] + '</li>';
        list2 += '<tr class =\"autocomplete-items\" onclick=\"myFunction(this.id)\" id='+k+'><td>' + k + ' - ' + availableTags[k] + '</td></tr>';
    }
       res.innerHTML = '<table id=\"tab\">' + list2 + '</table>';              
    })
    .catch(function(error) {
        console.log(error);
    }); 
}