const session_checker = angular.module("session_checker", []);

session_checker.controller('session_checkerCtrl', ['$scope', function($scope) {
  $scope.go_to_page_on_error = 
  $scope.check_session = function(){
    	var id = sessionStorage.getItem('id')
    	var apikey = sessionStorage.getItem('apikey')

    	if(id===null || apikey===null){
    		if(window.location.href !== location.origin + "/ui/pages/login/")
			window.location = location.origin + "/ui/pages/login";
		}else{
			if (window.location.href === location.origin + "/ui/pages/login/"){
				var _id = sessionStorage.getItem('id')
				if(_id=='admin'){
					//Go to admin's dashboard
					window.location = location.origin + "/ui/pages/admin";
				}else if(_id.includes('/')){
					//Go to auto-entity's dashboard
					window.location = location.origin + "/ui/pages/auto-entity";
				}else{
					//Go to owner's dashboard
					window.location = location.origin + "/ui/pages/owner";
				}
			}
		}

		var role = sessionStorage.getItem('role');
		if(role=='admin'){
    		if(window.location.href !== location.origin + "/ui/pages/admin/"){
    				window.location = location.origin + "/ui/pages/admin";
    		}
		}else if(role=='owner'){
			if (window.location.href !== location.origin + "/ui/pages/owner/"){
				window.location = location.origin + "/ui/pages/owner";
			}
		}else if(role=='auto-entity'){
			if (window.location.href !== location.origin + "/ui/pages/auto-entity/"){
				window.location = location.origin + "/ui/pages/auto-entity";
			}
		}/*else{
			window.location = location.origin + "/ui/pages/error/404";
		}	*/				
}
}]);