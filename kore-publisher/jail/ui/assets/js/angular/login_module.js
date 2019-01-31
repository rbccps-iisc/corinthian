const login = angular.module("login", ['footer', 'ui_urls', 'session_checker']);

login.controller('loginCtrl', function($scope, $http, origin, api){
    $scope.brand = "IUDX";
    $scope.brand_full_form = "Indian Urban Data Exchange";
    $scope.navbar_links = [
    	{"text":"Github","href":"https://github.com/rbccps-iisc/corinthian", "legend":"fab fa-github", "target": "_blank"},
    	{"text":"Documentation","href":"https://iudx.readthedocs.io/en/latest/", "legend":"fab fa-readme", "target": "_blank"},
    	// {"text":"iudx.org.in","href":"http://www.iudx.org.in/", "legend":"fas fa-receipt", "target": "_blank"}
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
				  var _dic;
				  var keys = Object.keys(response.data);
				  // console.log(response.data, keys)
				  if(_ROLE=='admin'){
				  	for (var i = keys.length - 1; i >= 0; i--) {
				  		_dic = {'own': keys[i], 'is_blocked': (response.data[keys[i]] ? true:false)};
					  	_data.push(_dic);
				  	}
				  }else if(_ROLE=='owner'){
				  	for (var i = keys.length - 1; i >= 0; i--) {
				  		_dic = {'ent':keys[i], 'is_blocked': (response.data[keys[i]][0] ? true:false), 'is_autonomous': (response.data[keys[i]][1] ? true:false)};
					  	_data.push(_dic);
				  	}
				  }else if(_ROLE=='entity'){
				  	
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
			$scope._login(api['entity']['login'], id, apikey, 'entity');
		}else{
			//Trigger owner login
			$scope._login(api['owner']['login'], id, apikey, 'owner');
		}
    };
});