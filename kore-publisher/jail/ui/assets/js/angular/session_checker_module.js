const session_checker = angular.module("session_checker", []);

session_checker.controller('session_checkerCtrl', ['$scope', function($scope) {
  $scope.check_session = function(){
    	// Remove saved data from sessionStorage
    	if(sessionStorage.getItem('id')===null || sessionStorage.getItem('apikey')===null)
		window.location = location.origin + "/ui/pages/login";
}
}]);