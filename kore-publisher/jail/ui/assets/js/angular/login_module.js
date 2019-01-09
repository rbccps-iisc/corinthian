const login = angular.module("login", ['footer', 'ui_urls']);

login.controller('loginCtrl', function($scope, $http, origin, api){
    $scope.brand = "IUDX";
    $scope.brand_full_form = "Indian Urban Data Exchange";
    $scope.navbar_links = [
    	{"text":"Link-1","href":"#", "legend":"planet"},
    	{"text":"Link-2","href":"#", "legend":"compass-04"},
    	{"text":"Link-3","href":"#", "legend":"diamond"}
    ];
    $scope.validateUser = function(){
    	let id = $scope.id;
    	let apikey = $scope.apikey;
    	let data ={}

    	if(id=='admin'){
			//Trigger admin login
			$http({
			    method: 'GET',
			    url: origin+api['admin']['login'],
			    data: {'test':'test'},
			    headers: {
			        // "X-Login-Ajax-call": 'true',
			        "id": id,
			        "apikey": apikey 
				}
			}).then(function(response) {
			    if (response.data == 'ok') {
			        // success
			        console.log(response)
			    } else {
			        // failed
			        console.log(response)
			    }
			});
		}else if(id.includes('/')){
			//Trigger auto entity login
		}else{
			//Trigger owner login
			$.ajax(

		    {

		    //url : 'https://smartcity.rbccps.org/api/0.1.0/publish',

		    url : origin+api['owner']['login'],

		    type: 'GET',

		    headers: {"id": id, "apikey": apikey},

		    dataType:"jsonp",

		    data: {},

		    //data: "{\"apikey\": \"eb91a7a83ed542a0aa7180608c5a2885\", \"body\": \"Sample Data from Sensor sensorOnboarding_101\", \"resourceid\":\"openday_application\"}",

		    success: function( data, textStatus, jQxhr ){
		      alert("Success" + data);
		    },

		    error: function( jqXhr, textStatus, errorThrown ){
		      //console.log( errorThrown + " | " + jqXhr + " | " + textStatus + " | ");
		      console.log(jqXhr);
		    }

		    });
			// $http({
			//     method: 'GET',
			//     url: origin+api['owner']['login'],
			//     data: {},
			//     headers: {
			//         // "X-Login-Ajax-call": 'true',
			//         "id": id,
			//         "apikey": apikey 
			// 	}
			// }).then(function(response) {
			//     if (response.data == 'ok') {
			//         // success
			//         console.log(response)
			//     } else {
			//         // failed
			//         console.log(response)
			//     }
			// });
		}
    	// alert(JSON.stringify(api));
        // alert("validateUser");
    };
});