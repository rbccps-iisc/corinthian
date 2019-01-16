const session_checker = angular.module("session_checker", []);

session_checker.controller('session_checkerCtrl', ['$scope', function($scope) {
  $scope.check_session = function(){
    	// Remove saved data from sessionStorage
    	var id = sessionStorage.getItem('id')
    	var apikey = sessionStorage.getItem('id')

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
}}
}]);