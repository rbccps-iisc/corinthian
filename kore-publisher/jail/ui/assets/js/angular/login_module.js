const login = angular.module("login", ['footer', 'ui_urls', 'session_checker']);

login.controller('loginCtrl', function($scope, $http, origin, api){
    $scope.brand = "IUDX";
    $scope.brand_full_form = "Indian Urban Data Exchange";
    $scope.navbar_links = [
    	{"text":"Link-1","href":"#", "legend":"planet"},
    	{"text":"Link-2","href":"#", "legend":"compass-04"},
    	{"text":"Link-3","href":"#", "legend":"diamond"}
    ];

    $scope.data=[]
    $scope._login=function(_URL, _ID, _APIKEY, _ROLE){
    	$http({
			    method: 'GET',
			    url: _URL,
			    headers: {
			        'id': _ID,
			        'apikey': _APIKEY,
			    },
			    contentType: 'application/json; charset=utf-8',
           		dataType: 'jsonp',
			    // data: {} 
			}).then(function (response)
            {
                $scope.response_data  = {'status':'Success'}; 
				if (typeof(Storage) !== "undefined") {
				  // Save user credentials to sessionStorage
				  sessionStorage.setItem("id", _ID);
				  sessionStorage.setItem("apikey", _APIKEY);
				  sessionStorage.setItem("role", _ROLE);
				  var _data = [];
				  var ent_dic;
				  console.log(response.data)
				  if(_ROLE=='admin'){
				  	for (var i = response.data.length - 1; i >= 0; i--) {
				  		ent_dic = {'own': response.data[i]};
				  		_data.push(ent_dic);
				  	}
				  }else if(_ROLE=='owner'){
				  	for(var i in response.data){
					  	ent_dic = {'ent':Object.keys(response.data[i])[0], 'is_autonomous':Object.values(response.data[i])[0], 'index': Object.keys(response.data[i])[0].replace("/","_")};
					  	_data.push(ent_dic);
					 }
				  }else if(_ROLE=='auto-entity'){
				  	
				  }
				  
				  localStorage.setItem("data", JSON.stringify(_data));
				  window.location = location.origin + "/ui/pages/"+_ROLE;
				} else {
				  // Sorry! No Web Storage support..
				  alert("Sorry! No Web Storage support.");
				}
                // console.log(typeof(response.data))
            }, function(error){
            	 $scope.response_data = {'status': "Error: " + error['data']['error']}; 
            	 // window.location = location.origin + "/ui/pages/login";
                 // console.log(error, error['data']['error']); 
            });
    }

    $scope.validateUser = function(){
    	let id = $scope.id;
    	let apikey = $scope.apikey;
    	let data ={}
    	if(id=='admin'){
			//Trigger admin login
			$scope._login(api['admin']['login'], id, apikey, 'admin');
			
		}else if(id.includes('/')){
			//Trigger auto entity login
			$scope._login(api['auto-entity']['login'], id, apikey, 'auto-entity');
		}else{
			//Trigger owner login
			$scope._login(api['owner']['login'], id, apikey, 'owner');
		}
    };
});