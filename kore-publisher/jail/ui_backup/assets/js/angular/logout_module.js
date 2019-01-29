const logout = angular.module("logout", []);

logout.controller('logoutCtrl', ['$scope', function($scope) {
  $scope._logout = function(){
    	// Remove saved data from sessionStorage
		sessionStorage.clear();
		localStorage.clear();
		window.location = location.origin + "/ui/pages/login";
}
}]);