const login = angular.module("login", ['footer', 'ui_urls', 'session_checker']);

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
			
		}else if(id.includes('/')){
			//Trigger auto entity login
		}else{
			$http({
			    method: 'GET',
			    url: api['owner']['login'],
			    headers: {
			        'id': id,
			        'apikey': apikey,
			    },
			    // data: {} 
			}).then(function (response)
            {
                $scope.response_data  = {'status':'Success', 'data': response.data}; 
				if (typeof(Storage) !== "undefined") {
				  // Save user credentials to sessionStorage
				  sessionStorage.setItem("id", id);
				  sessionStorage.setItem("apikey", apikey);
				  window.location = location.origin + "/ui/pages/admin";
				} else {
				  // Sorry! No Web Storage support..
				  alert("Sorry! No Web Storage support.");
				}
                // console.log(response.data)
            }, function(error){
            	 $scope.response_data = {'status': "Error: " + error['data']['error'], 'data': error['data']}; 
            	 // window.location = location.origin + "/ui/pages/login";
                 // console.log(error, error['data']['error']); 
            });
			
		}
    };
});